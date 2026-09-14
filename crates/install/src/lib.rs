//! `habitat-install` -- installer and launch-time preflight checks.
//!
//! Phase 1 responsibility (see `tmp/wip/implementation-plan.md`):
//! - `habitat install`: detect/verify Podman, verify the `krun` runtime
//!   binary (shipped by the `crun-krun` package -- package and binary are
//!   named differently, confirmed on real Fedora hardware; see
//!   `checks::krun_runtime`) is available, refuse explicitly on non-Linux
//!   hosts (see `docs/decisions/0003-container-engine-runtime-layer.md`).
//! - `habitat run`'s preflight subroutine: real KVM/hardware-virtualization
//!   capability probe, Podman/krun-runtime reachability check. Every check
//!   fails closed -- names the specific failed check, exits non-zero, logs
//!   to the audit destination tagged as a distinct preflight-failure event
//!   (AGENTS.md Section 2, invariant 11).
//!
//! Module layout:
//! - [`environment`] -- the `Environment` seam between checks and the real
//!   machine (real implementation + an in-memory fake for tests).
//! - [`checks`] -- the four individual, named checks.
//! - [`preflight`] -- assembles checks into `habitat install`'s and
//!   `habitat run`'s entry points, wiring in the audit sink. Also exposes
//!   [`install_report`]/[`preflight_report`], a non-short-circuiting,
//!   unaudited pass over the same checks so the CLI can print a full
//!   checklist (what's present, what isn't) rather than surfacing one
//!   failure at a time.
//! - [`package_manager`] -- detects the host's dnf/apt package-manager
//!   family (`docs/decisions/0001-host-os-layer.md`'s 2026-09-14
//!   amendment), used only by [`installer`].
//! - [`installer`] -- `habitat install`'s optional, opt-in auto-install
//!   step: runs the actual `sudo dnf|apt-get install` command for
//!   whichever check is missing, once the operator has confirmed. This is
//!   the one part of the crate that mutates the host; `checks`/`preflight`
//!   stay verify-only.

pub mod checks;
pub mod environment;
pub mod installer;
pub mod package_manager;
pub mod preflight;

pub use checks::{CheckFailure, CheckId};
pub use environment::{testing, Environment, SystemEnvironment};
pub use installer::{install_missing, InstallAttempt};
pub use package_manager::{detect_package_family, package_for, PackageFamily};
pub use preflight::{
    install_report, preflight_report, run_install_checks, run_preflight, CheckStatus,
    PreflightError,
};
