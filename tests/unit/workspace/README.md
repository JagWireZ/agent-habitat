# tests/unit/workspace/

Unit tests mirroring `crates/workspace/`.

`exit_gate.rs` holds Phase 2's contract-with-the-rest-of-the-system
tests for the git-history toggle (defaults off; flipping it on without a
complete logged approval entry is a hard failure of the whole
`pipeline::build` call, verified end-to-end, not just at the lower-level
`habitat_policy::git_history::resolve` unit tests inline in that crate).
The other Phase 2 exit-gate requirement -- blocklisted files never
reaching the staging directory (the same directory later bind-mounted
into the guest) -- lives in `tests/adversarial/blocklist_disk_image.rs`
instead, alongside Phase 3/5's adversarial tests, per `file-structure.md`.

Phase 4 (two-point sync) adds more logic, and therefore more tests, here
later.

`content_scan_exit_gate.rs` holds the exit gate for content-based secrets
scanning (Betterleaks): the enabled/disabled flag is respected, scanning
fails closed when the `betterleaks` binary isn't installed, the effective
ruleset snapshot written per build merges the bundled baseline with a
project's own `betterleaks.toml`, and a real (stub) `betterleaks` on
`PATH` blocks exactly the file carrying a finding. A project ruleset
attempting to weaken or disable detection is covered adversarially
instead, in `tests/adversarial/content_scan_ruleset_tamper.rs`.

`agent_state_exit_gate.rs` holds the contract tests for agent auth/config
copying (`habitat_workspace::agent_state`, `docs/decisions/
0011-agent-state-copy-in-out.md`): auth files go in and come back out,
config files go in only, a named-agent session only ever receives that
agent's files, an unchanged file is not rewritten or re-logged, a missing
guest file never deletes the host copy, a second concurrent session never
copies out, host directories are created `0700`, and audit records carry
paths and fingerprints but never contents. The guest is a `FakeGuest`
backed by a real temporary directory, so the filesystem logic runs for
real; the real `ssh`/`scp` round trip is `tests/manual/
validate-agent-state.md`. Hostile-guest cases live in
`tests/adversarial/agent_state_copy_out.rs`.
