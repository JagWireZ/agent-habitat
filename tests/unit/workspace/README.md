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
