//! `habitat-workspace` -- the disk-build pipeline and the two-point sync.
//!
//! Phase 2 (done): [`pipeline::build`] sequences the stages below.
//! - [`staging`]: project copy -> secrets blocklist filter (defaults and
//!   matching rule live in `habitat_policy::blocklist`, extended
//!   per-project via `habitat_policy::config`), applied *before* the
//!   session's disposable disk exists -- no "build then scrub" step
//!   (AGENTS.md Section 2, invariant 2).
//! - [`gitseed`]: seeds a synthetic git repo by default, or copies the
//!   real `.git` read-only when the checked-in config's git-history
//!   toggle is on and resolved (`habitat_policy::git_history`) --
//!   resolution fails closed without a logged approval entry.
//! - [`diskimage`]: assembles the staged files into the session's
//!   disposable raw disk image (`docs/decisions/0005-storage-layer.md`).
//!
//! Phase 4 responsibility (not yet built):
//! - Host->sandbox sync immediately before each prompt, sandbox->host sync
//!   immediately after each tool call, both via the same trusted patch
//!   mechanism, both re-checked against the blocklist on arrival
//!   (AGENTS.md Section 2, invariants 1, 3, 10).
//! - No live/continuous file-share process at any point.

pub mod command_runner;
pub mod diskimage;
pub mod gitseed;
pub mod pipeline;
pub mod staging;
