//! `habitat-workspace` -- the disk-build pipeline and the two-point sync.
//!
//! Phase 2 responsibility (see `tmp/wip/implementation-plan.md`):
//! - Read the shared secrets blocklist from `policy/` (via `habitat-policy`)
//!   and apply it *before* the session's disposable virtual disk exists --
//!   no "build then scrub" step (AGENTS.md Section 2, invariant 2).
//! - Seed a synthetic git repo by default, or mount the real `.git`
//!   read-only when the checked-in config's git-history toggle is on.
//!
//! Phase 4 responsibility:
//! - Host->sandbox sync immediately before each prompt, sandbox->host sync
//!   immediately after each tool call, both via the same trusted patch
//!   mechanism, both re-checked against the blocklist on arrival
//!   (AGENTS.md Section 2, invariants 1, 3, 10).
//! - No live/continuous file-share process at any point.
//!
//! No logic yet -- Phase 0 scaffolding only.
