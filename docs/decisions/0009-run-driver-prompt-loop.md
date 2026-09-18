# 0009. `habitat run`'s session driver: one discrete guest-exec per prompt, not a PTY-attached interactive process

Status: accepted
Date: 2026-09-18

## Context

`docs/plan.md` describes syncing "before each prompt" and "after each tool
call," and its usage example is `habitat run -- claude-code` -- but no
earlier phase defined what a "prompt" or a "tool call" actually *is* from
`habitat run`'s point of view when the agent named after `--` is an
arbitrary, opaque CLI. Phases 1-6 built every subsystem `habitat run`
needs (preflight, disk build, VM launch/teardown, two-point sync, egress,
audit) as clean, independently-tested library APIs, but none of them
assumed a process model for the agent itself, because none of them needed
one.

Two process models were considered:

1. **PTY-attached interactive passthrough.** `habitat run` opens an
   interactive SSH session into the guest, runs the named agent command
   there with the operator's own terminal attached (a pty), and tries to
   detect "prompt" and "tool call" boundaries by watching the agent's
   output for some signal that a turn started or ended.
2. **Discrete per-prompt exec.** `habitat run` reads one line of operator
   input at a time (one "prompt"), and for each one: sync host->sandbox,
   run the agent as a single, complete `ssh` invocation via the existing
   `GuestExecRunner` (the same "one discrete invocation per guest
   interaction, no persistent connection" mechanism `crates/workspace::sync`
   and `docs/decisions/0008-guest-exec-channel.md` already use for
   everything else that touches the guest), sync sandbox->host once that
   invocation returns, then loop.

Option 1 has no reliable way to detect an arbitrary CLI's internal turn
boundaries without instrumenting that CLI specifically -- there is no
generic signal a wrapper process can watch for. It would also require
introducing this project's first long-lived, persistent connection to the
guest (an interactive SSH session held open for the whole operator
session), which cuts against invariant 1 (no live, always-on
host<->sandbox channel) in spirit even if the *sync* mechanism itself
stayed the same underneath it.

Option 2 fits the architecture every prior phase already built: the guest
is only ever reached through short, discrete `ssh`/`scp` invocations, and
this project has consistently chosen "one discrete call per interaction"
over a persistent channel (invariant 1; `0008`'s own "still one discrete
invocation per guest interaction" consequence). It also composes directly
with the existing `sync_host_to_sandbox` / `sync_sandbox_to_host` /
`GuestExecRunner` APIs with no new guest-side mechanism at all.

## Decision

`habitat run -- <agent> [agent-args...]`'s prompt loop is:

1. Read one line from the operator's stdin. Treat it as one prompt. EOF or
   an explicit `exit`/`quit` line ends the session (falls through to
   teardown).
2. `sync::sync_host_to_sandbox` -- exactly the existing API, unchanged.
3. Run the agent as one discrete guest exec:
   `GuestExecRunner::exec(<agent-program>, [...agent-args, <prompt>])`,
   inside `sync::GUEST_WORKSPACE_DIR`. This is a single blocking SSH
   invocation that runs to completion and returns its full stdout/stderr
   at the end -- there is no live streaming of the agent's output while
   it's still working on a turn. `<agent-program>` must accept a single
   prompt as a final positional argument and exit when it's answered that
   prompt (a "one-shot" invocation mode) -- it is not run as a persistent,
   multi-turn interactive process across the whole session.
4. `sync::sync_sandbox_to_host` -- exactly the existing API, unchanged.
5. Print the agent's stdout/stderr to the operator, then go to step 1.

This resolves "after each tool call" to "after each prompt's full agent
invocation returns" -- coarser than literal per-tool-call granularity,
since a discrete, non-instrumented exec can't observe the agent's
internal tool-call boundaries during that one invocation. This is a
deliberate, recorded approximation, not a silent scope-narrowing: v1
syncs once per prompt round-trip, not once per internal tool call inside
it. If per-tool-call granularity is needed later, it requires either
agent-side instrumentation (a hook the agent calls out to per tool call)
or a fundamentally different process model (option 1 above, revisited
with a concrete detection mechanism) -- not a small change to this
driver.

## Consequences

- No new persistent connection to the guest is introduced; the loop only
  ever holds `sync_host_to_sandbox`, one `exec`, and
  `sync_sandbox_to_host` open at a time, each already a short-lived
  discrete invocation.
- The agent named after `--` must support a one-shot, single-prompt
  invocation mode (e.g. `claude-code --print "<prompt>"`-shaped, not an
  interactive REPL). Documenting this requirement for operators is part
  of Phase 7's CLI UX deliverable. An agent that only offers a persistent
  interactive REPL is not supported by this driver without a wrapper of
  its own; that's a real limitation of v1, not solved here.
- No live streaming: the operator sees nothing from the agent until its
  entire turn (potentially involving many internal tool calls) has
  finished and the SSH invocation returns. For a long turn this reads as
  a silent pause, not a working indicator. Acceptable for v1; a real,
  recorded limitation rather than an oversight.
- Egress proxy/DNS-forwarder processes and the per-session firewall rules
  (Phase 5) are started once at session setup (before the first prompt)
  and torn down once at session end -- they are boundary infrastructure
  for the whole session's lifetime, not something scoped per prompt.
  Neither `crates/egress::proxy::run` nor `crates/egress::dns::run`
  exposes a graceful-shutdown mechanism usable from outside the process
  (`proxy::run`'s accept loop blocks on `TcpListener::incoming()`
  indefinitely); this decision does not add one. Both run on detached
  background threads for the life of the `habitat run` process and are
  reclaimed when that process exits after teardown completes. Only the
  host-visible resources teardown is actually responsible for --
  the podman container, the disk image, the session SSH keypair, and the
  session's nftables rules -- are explicitly removed.
- `audit: disabled` (`habitat_policy::config::ProjectConfig::audit`,
  Phase 7's other new config key) only suppresses the audit trail's
  routine/low-signal events (`EventKind::is_suppressible_when_audit_disabled`
  in `habitat-audit`): `PreflightPass`, `InstallPass`, `SyncApplied`,
  `EgressAllowed`, `InstallAction`. It can never suppress
  `PreflightFailure`, `InstallFailure`, `SyncFlagged`,
  `EgressDenied`, `ContentRulesetMidSessionEdit`, `SessionStart`, or
  `SessionStop` -- AGENTS.md invariants 3, 10, 11, and 12 all assume those
  stay visible regardless of any config value, so this toggle is scoped
  as a verbosity control on the log, never a way to turn off the boundary
  audit trail itself.
- An egress denial is log-only from the operator's point of view: it
  surfaces to the agent's own tooling as a failed network call (a normal
  connection failure from the guest's side), not as an interrupt to the
  `habitat run` process itself. The operator finds out about it from the
  audit log (`EgressDenied`, already emitted per-connection since Phase
  5), same as any other boundary event -- there is no additional
  operator-facing pop-up wired into the prompt loop for this.
