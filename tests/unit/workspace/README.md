# tests/unit/workspace/

Unit tests mirroring `crates/workspace/`.

`exit_gate.rs` holds Phase 2's contract-with-the-rest-of-the-system
tests for the git-history toggle (defaults off; flipping it on without a
complete logged approval entry is a hard failure of the whole
`pipeline::build` call, verified end-to-end, not just at the lower-level
`habitat_policy::git_history::resolve` unit tests inline in that crate).
The other Phase 2 exit-gate requirement -- blocklisted files never
reaching the disk image or the staging artifact -- lives in
`tests/adversarial/blocklist_disk_image.rs` instead, alongside Phase
3/5's adversarial tests, per `file-structure.md`.

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
