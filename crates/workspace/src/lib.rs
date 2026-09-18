//! `habitat-workspace` -- the disk-build pipeline and the two-point sync.
//!
//! [`pipeline::build`] sequences [`staging`] (project copy, filtered
//! through `habitat_policy::blocklist`/`config` *before* the disposable
//! disk exists -- AGENTS.md Section 2, invariant 2), [`gitseed`] (synthetic
//! repo by default, or the real `.git` read-only per
//! `habitat_policy::git_history`, failing closed), and [`diskimage`]
//! (assembles the raw disk image, `docs/decisions/0005-storage-layer.md`).
//!
//! [`sync`] implements the two-point host<->sandbox sync -- host->sandbox
//! before each prompt, sandbox->host after each tool call, both via
//! [`patch`], both re-checked against the blocklist (AGENTS.md Section 2,
//! invariants 1, 3, 10). No continuous file-share process: every guest-side
//! step is one discrete `podman exec`/`podman cp` ([`guest_exec`]).
//!
//! [`content_scan`] shells out to `betterleaks` from [`staging`] at the
//! same enforcement point as the filename blocklist; [`pipeline`] resolves
//! the ruleset via `habitat_policy::secrets_scan`. A sandbox->host patch
//! touching a project's `betterleaks.toml` is routed through the
//! flagged-for-review path in [`sync`]'s validation gate rather than
//! silently updating the governing snapshot -- see
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
