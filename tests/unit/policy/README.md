# tests/unit/policy/

Unit tests mirroring `crates/policy/`.

Phase 2's tests for `blocklist.rs`, `git_history.rs`, and `config.rs` are
pure internal logic (glob matching, toggle resolution, a hand-rolled
parser) with no contract-with-the-rest-of-the-system shape to them, so
per `file-structure.md` they live as inline `#[cfg(test)]` modules in
each of those files instead of here -- same split `crates/install`
already established in Phase 1. This directory stays empty until a
policy-crate test genuinely needs to live outside the crate (e.g. a
cross-crate exit-gate test, the way `crates/workspace`'s does).
