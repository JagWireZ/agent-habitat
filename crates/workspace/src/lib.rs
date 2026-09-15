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
//!
//! Content-based secrets scanning (Betterleaks, alongside the filename
//! blocklist): [`content_scan`] shells out to the `betterleaks` binary,
//! called from [`staging`] at the exact same enforcement point the
//! filename blocklist already uses (before a file is ever copied into
//! staging). [`pipeline`] resolves the effective ruleset once per build
//! via `habitat_policy::secrets_scan`, mirroring Phase 2's blocklist
//! wiring. **Not yet built, and explicitly out of scope here**: the
//! Phase 4 half of this feature -- snapshotting a project's own
//! `betterleaks.toml` once at session start and routing a later
//! sandbox->host edit to it through the "flagged for review" patch path
//! instead of silently updating the governing snapshot -- depends on the
//! two-point sync mechanism above, which doesn't exist yet. See
//! `docs/decisions/0007-content-secrets-scan-snapshot.md`.

pub mod command_runner;
pub mod content_scan;
pub mod diskimage;
pub mod gitseed;
pub mod pipeline;
pub mod staging;
