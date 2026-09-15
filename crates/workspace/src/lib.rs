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
//! Phase 4 (done): [`sync`] implements the two-point host<->sandbox sync --
//! host->sandbox immediately before each prompt, sandbox->host immediately
//! after each tool call, both via the same trusted patch mechanism
//! ([`patch`]), both re-checked against the blocklist and structurally
//! validated on arrival (AGENTS.md Section 2, invariants 1, 3, 10). No
//! live/continuous file-share process at any point -- every guest-side
//! step is one discrete `podman exec`/`podman cp` invocation
//! ([`guest_exec`]).
//!
//! Content-based secrets scanning (Betterleaks, alongside the filename
//! blocklist): [`content_scan`] shells out to the `betterleaks` binary,
//! called from [`staging`] at the exact same enforcement point the
//! filename blocklist already uses (before a file is ever copied into
//! staging). [`pipeline`] resolves the effective ruleset once per build
//! via `habitat_policy::secrets_scan`, mirroring Phase 2's blocklist
//! wiring. The Phase 4 half of this feature -- a sandbox->host patch
//! touching a project's `betterleaks.toml` routed through the flagged-
//! for-review path rather than silently updating the governing snapshot
//! -- is implemented in [`sync`]'s validation gate; see
//! `docs/decisions/0007-content-secrets-scan-snapshot.md`.

pub mod command_runner;
pub mod content_scan;
pub mod diskimage;
pub mod gitseed;
pub mod guest_exec;
pub mod patch;
pub mod pipeline;
pub mod staging;
pub mod sync;
