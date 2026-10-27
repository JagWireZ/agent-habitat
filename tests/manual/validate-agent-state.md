# validate-agent-state.md -- real-hardware exit gate for agent state copying

Status: NOT YET RUN. `docs/decisions/0011-agent-state-copy-in-out.md` stays
`proposed` until every step below has been run on a real host and the
results recorded at the bottom (`AGENTS.md` Section 3, "verify before
trusting").

What this covers that the automated tests cannot: the real `ssh`/`scp`
round trip into a booted `krun` guest, ownership and modes of the copied
files inside the guest, and each agent actually working from them.
`tests/unit/workspace/agent_state_exit_gate.rs` and
`tests/adversarial/agent_state_copy_out.rs` already cover the host-side
logic against a fake guest.

Prerequisites: a validated AlmaLinux (or later-stage) host with `/dev/kvm`,
the guest image built (`guest/build.sh`), and `habitat` built from this
change. Use a throwaway `$HOME` so real credentials are never involved:

```
export HABITAT_TEST_HOME="$(mktemp -d)"
export HOME="$HABITAT_TEST_HOME"
```

Do not use real provider credentials for steps 1-6; use obviously fake
tokens. Step 7 needs one real login per agent you want to confirm.

## 1. Directories are private

Run `habitat run` (shell mode), then `exit` immediately.

- [ ] `stat -c '%a' ~/.habitat ~/.habitat/agents ~/.habitat/agents/*`
      prints `700` for every line.

## 2. Copy-in lands the files, owned by `habitat`, with the right modes

Before running, create fake host files:

```
mkdir -p ~/.habitat/agents/codex/.codex ~/.habitat/agents/claude/.claude
printf '{"refresh":"fake-codex"}' > ~/.habitat/agents/codex/.codex/auth.json
printf 'a = 1\n'                  > ~/.habitat/agents/codex/.codex/config.toml
printf '{"claudeAiOauth":{}}'     > ~/.habitat/agents/claude/.claude/.credentials.json
mkdir -p ~/.habitat/agents/claude/.claude/commands
printf 'review'                   > ~/.habitat/agents/claude/.claude/commands/r.md
```

Run `habitat run` (shell mode). Inside the guest:

- [ ] `ls -l ~/.codex/auth.json ~/.claude/.credentials.json` -- owned by
      `habitat`, mode `-rw-------` on both.
- [ ] `cat ~/.codex/auth.json` prints the fake token; `~/.codex/config.toml`
      and `~/.claude/commands/r.md` are present.
- [ ] `mount | grep -c ' /home/habitat'` prints `0` -- no bind mount under
      the guest home. `mount | grep workspace` shows only `/workspace`.

## 3. Per-agent scoping

Run `habitat run codex` (agent mode) with a one-shot prompt that runs
`ls -la ~` in the guest (or a custom `-- sh -c 'ls -la ~'` agent).

- [ ] With `habitat run codex`, `~/.codex/auth.json` exists and
      `~/.claude/.credentials.json` does NOT.
- [ ] With a custom `habitat run -- sh -c 'ls -a ~'` agent, neither exists.

## 4. Auth copy-out (refresh and first login)

In shell mode, inside the guest:

```
printf '{"refresh":"rotated-in-guest"}' > ~/.codex/auth.json
```

- [ ] Within about 30 seconds (one tick pass) the host's
      `~/.habitat/agents/codex/.codex/auth.json` contains
      `rotated-in-guest`, mode `600`.
- [ ] Exit the shell; confirm the final pass also wrote anything changed in
      the last seconds (write again right before `exit`).
- [ ] Delete `~/.habitat/agents/codex` entirely, start a new shell session,
      write a fresh `~/.codex/auth.json` in the guest, exit: the host file is
      created `0600` inside `0700` directories (first login inside a guest).

## 5. Config is copy-in only

In shell mode, inside the guest, modify `~/.codex/config.toml` and create
`~/.claude/commands/planted.md`, then exit.

- [ ] The host's `config.toml` is unchanged and `planted.md` does not exist
      anywhere under `~/.habitat/agents/`.

## 6. Hostile-looking guest output is refused

In shell mode, inside the guest:

```
printf 'not json' > ~/.codex/auth.json
```

- [ ] The host's token file is unchanged and a line
      `agent-state-rejected` appears in the audit log
      (`~/.local/state/habitat/audit.log`), exactly once however long the
      shell stays open.
- [ ] `head -c 9000000 /dev/zero > ~/.codex/auth.json` in the guest is
      rejected the same way and the host `habitat` process does not grow
      unreasonably (watch `ps -o rss`).

## 7. Each agent starts authenticated from the copied files

For each agent, log in once inside a guest, exit, then start a NEW session:

- [ ] `claude`: `habitat run claude` does not prompt to log in again.
      Record whether it still asks to trust `/workspace` and re-run
      onboarding (this informs the deferred "strip `projects`" decision in
      the ADR).
- [ ] `codex`: confirm whether login persisted. If the host has no
      `auth.json` after login, Codex stored the credential somewhere else
      (e.g. a keyring); check whether
      `cli_auth_credentials_store = "file"` is needed in `config.toml`.
- [ ] `opencode`: after `opencode auth login`, the host has
      `~/.habitat/agents/opencode/.local/share/opencode/auth.json`.

## 8. Concurrent sessions

Start `habitat run codex` in two terminals.

- [ ] Both start and are authenticated (copy-in works for both).
- [ ] Only the first copies out: a token change in the second session's
      guest does NOT reach the host, and the audit log holds exactly one
      `agent-state-rejected` line naming the lock.
- [ ] After the first session exits, a third session can copy out again.

## 9. Teardown and SELinux

- [ ] `podman ps -a` shows no leftover container; no staging directory
      remains.
- [ ] On an SELinux-enforcing host, no `:z` relabeling of `~/.habitat`
      happened: `ls -Z ~/.habitat/agents` shows the normal home-directory
      context, not `container_file_t`.
- [ ] The launch's `podman run` argv (audit log or `ps`) contains exactly one
      `-v` flag.

## Record

Date / host / `habitat` build / who ran it, and the result of every checkbox
above (including anything that behaved differently than the ADR assumes).
When complete and green, change 0011's Status to `accepted`.

```
(not yet recorded)
```
