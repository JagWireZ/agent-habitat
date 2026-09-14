//! `habitat-install` -- installer and launch-time preflight checks.
//!
//! Phase 1 responsibility (see `tmp/wip/implementation-plan.md`):
//! - `habitat install`: detect/verify Podman, verify the `krun` runtime
//!   (`crun-krun`, backed by libkrun) is available, refuse explicitly on
//!   non-Linux hosts (see `docs/decisions/0005-rootless-podman-krun-virtualization-stack.md`).
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

pub mod checks;
pub mod environment;
pub mod preflight;

pub use checks::{CheckFailure, CheckId};
pub use environment::{testing, Environment, SystemEnvironment};
pub use preflight::{
    install_report, preflight_report, run_install_checks, run_preflight, CheckStatus,
    PreflightError,
};
