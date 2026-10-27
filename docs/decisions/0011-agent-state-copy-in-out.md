# 0011. Agent auth and config state: copied in and out over SSH, not bind-mounted

Status: proposed
Date: 2026-10-27

Moves to `accepted` once `tests/manual/validate-agent-state.md` has been
run on real hardware and its results recorded, per `AGENTS.md` Section 3.
Everything below the guest boundary (the real `ssh`/`scp` round trip, the
agents' own behavior on the copied files) is untested until then; the host
side is covered by `tests/unit/workspace/agent_state_exit_gate.rs`,
`tests/adversarial/agent_state_copy_out.rs`, and
`tests/integration/run_session_end_to_end.rs`.

## Context

The coding agents `habitat run` knows about (`claude`, `codex`,
`opencode`) keep their login and configuration in files under the
guest user's home: `~/.claude.json`, `~/.claude/`, `~/.codex/`,
`~/.config/opencode/`, and (for opencode's credentials)
`~/.local/share/opencode/`. A disposable VM per session means every login
is lost at teardown unless something persists it.

The first implementation bind-mounted `~/.habitat/{claude,claude.json,
codex,opencode}` from the host into those guest paths. It was never
recorded in an ADR, and it has problems that matter for this project:

- It is a second live host/guest channel for the whole session. `AGENTS.md`
  Section 2 invariant 1 is about the *project* directory, but the reasoning
  behind it (no continuous bridge; every crossing discrete and auditable)
  applies to credentials at least as strongly.
- A mount exposes a whole subtree read-write. Because Claude Code's and
  Codex's directories hold behavior-affecting files (hooks, MCP servers,
  instruction files, skills), a compromised session could rewrite them and
  every later session, on every project, would load the result -- persistence
  of compromise across the "disposable" boundary.
- Getting the guest user able to write host-owned files needed
  `chmod -R a+rwX` in `guest/entrypoint.sh`, which rewrote permissions on
  the operator's credential files, and SELinux needed `:z` relabeling of
  host paths.
- `~/.claude.json` as a single-file mount is fragile: tools that write by
  rename cannot replace a bind-mounted file.
- opencode's credentials live in `~/.local/share/opencode/`, which was never
  mounted, so opencode logins did not persist at all.
- Every existing auth path was mounted regardless of which agent ran, so a
  `claude` session could read the Codex token.
- Two concurrent sessions shared one mutable token file, racing on rotating
  OAuth refresh tokens.

## Decision

Agent state is **copied**, file by file, over the per-session SSH channel
`0008-guest-exec-channel.md` already provides. Nothing about it is a bind
mount; `launcher::build_run_args` emits exactly one `-v`, for the workspace
staging directory.

**What may move is a fixed manifest**, `policy/agent_state.txt`, baked into
the binary and loaded by `habitat_policy::agent_state`. Each entry names an
agent, a role, a kind, and a path relative to the guest home. It is not
extensible from a project's `sandbox.yaml`, and any change to it is reviewed
on the quarterly pass.

**Direction depends on role:**

- `auth` files (OAuth tokens, API keys, account identity) are copied host to
  guest at launch, and guest to host after each prompt round, periodically
  during an interactive shell session, and once more before teardown --
  because refresh tokens rotate while an agent runs, and a first login may
  happen inside the guest.
- `config` files and directories are copied host to guest at launch **only**.
  They are never copied back.

**Scope is per agent.** A named-agent session (`habitat run claude`)
receives only that agent's entries. A custom `-- <program>` agent receives
none. An interactive shell session receives every agent's.

**Host layout.** `~/.habitat/agents/<agent>/<home-relative-path>`, so a
manifest entry is the same relative path on both sides. `~/.habitat`,
`agents/`, and each agent directory are `0700`; files are `0600`.

**Copy-in** is `mkdir -p` (one `ssh`), then `scp` per file or `scp -r` per
config directory, then `chmod 600` on auth files. Host paths that are
symlinks are refused, wrong types are refused, and a config directory is
walked first and refused whole if it contains a symlink, a special file, a
control character in a name, or exceeds the size/count/depth limits (because
`scp -r` follows symlinks on the sending side). A missing host path is
skipped.

**Copy-out treats the guest as hostile.** There is no guest-to-host `scp`.
The host runs `head -c <cap+1> -- <path>` over `ssh` and does everything
else itself: a size cap, an empty-file refusal, a UTF-8 check (and a parse
to a JSON object for `.json` files, via `serde_json`), refusal to write
through a symlink or onto a non-regular file, then a `0600` temp file in the
same directory and an atomic rename. A missing guest file never deletes the
host copy. Unchanged content is not rewritten or re-logged (fingerprint
comparison); a persistently bad file is logged once, not per tick.

**Concurrency.** Each agent directory holds a `.lock` taken with
`File::try_lock` for the session's lifetime. A second concurrent session for
the same agent still gets its copy-in but never copies out, and logs that
once. Two sessions never race on one rotating token.

**Audit.** Three non-suppressible event kinds -- `agent-state-copied-in`,
`agent-state-copied-out`, `agent-state-rejected` -- record the agent, the
manifest path, and a change-detection fingerprint. File contents are never
logged.

**Failure is visible but not fatal.** A failed or refused copy is printed
and audited and leaves the agent unauthenticated; it never aborts a session
or blocks teardown.

## Consequences

- `AuthMount`, `LaunchRequest::auth_mounts`, the launcher's auth-source
  creation and `:z` relabeling, `known_auth_mounts` /
  `ensure_auth_entries_exist`, and the entrypoint's auth `chmod -R` loop are
  removed. The "exactly one bind mount" assertions in
  `tests/adversarial/containment_escape.rs` are true in production again.
  The workspace mount's `:Z` relabel stays.
- Provider credentials are now the one deliberate exception to "secrets never
  go in" (`docs/plan.md`). They move only through this manifest, only over
  the authenticated per-session channel, and every crossing is audited.
- Persistence of compromise through config is closed: a session cannot alter
  what a later session's agent loads. A compromised session can still
  tamper with the *auth* files it is allowed to send back; copy-out validation
  bounds that to a well-formed, size-limited file in the agent's own
  credential location, which is the same trust the agent already needs.
- `~/.claude.json` is copied as one file, including its per-project map.
  Every project is `/workspace` inside the guest, so per-project trust and
  history entries accumulate across projects. Stripping that key on
  copy-out is a candidate follow-up; it is not done here because its effect
  on Claude Code's startup prompts is unverified.
- Logging out inside the guest does not log out on the host (a missing guest
  file never deletes the host copy).
- A hard crash of `habitat` itself loses at most the token changes since the
  last copy-out pass (one prompt round, or about 30 seconds in a shell
  session). A rotated refresh token lost that way means logging in again.
- **Limits that remain.** A hostile guest can make `ssh` emit unbounded
  stdout, which the `CommandRunner` seam buffers in memory; `head -c` bounds
  an honest guest only. This is the same exposure every guest `exec` in
  `habitat-workspace` already has. Audit fingerprints are SipHash change
  detectors, not cryptographic digests, so they are not tamper evidence.
- **Migration.** Existing `~/.habitat/claude`, `claude.json`, `codex`, and
  `opencode` are not read any more. Move them by hand:
  `~/.habitat/claude/*` to `~/.habitat/agents/claude/.claude/`,
  `~/.habitat/claude.json` to `~/.habitat/agents/claude/.claude.json`,
  `~/.habitat/codex/*` to `~/.habitat/agents/codex/.codex/`, and
  `~/.habitat/opencode/*` to
  `~/.habitat/agents/opencode/.config/opencode/` (opencode credentials move
  to `.local/share/opencode/` -- they were never persisted before).
  Only manifest paths are used; everything else in the old directories
  (history, transcripts, caches) is deliberately left behind.
- A new dependency, `serde_json`, is added to `habitat-workspace` for the
  copy-out JSON check. `habitat-audit` stays dependency-free and still
  hand-escapes its own output. Add it to the dependency catalogue on the next
  quarterly pass.

## Deferred (`AGENTS.md` Section 4 style -- not built)

- An `import` command that seeds `~/.habitat/agents/` from the operator's real
  `~/.claude` etc. Not built because it would carry host-specific hooks and
  `apiKeyHelper` scripts into the guest. Trigger: operators repeatedly
  hand-copying files and asking for it.
- Stripping `projects` from `.claude.json` on copy-out. Trigger: confirmed
  cross-project trust or history leakage in real use.
- Streaming guest output with a hard host-side byte cap instead of buffering
  `ssh` stdout. Trigger: any change to the `CommandRunner` seam that makes
  bounded reads cheap, or a demonstrated host memory problem.
