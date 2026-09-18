//! `habitat-install` -- installer and launch-time preflight checks.
//!
//! Every check fails closed: names the specific failed check, exits
//! non-zero, and logs to the audit destination as a distinct
//! preflight-failure event (AGENTS.md Section 2, invariant 11).
//!
//! Module layout:
//! - [`environment`] -- the `Environment` seam between checks and the real
//!   machine (real implementation + an in-memory fake for tests).
//! - [`checks`] -- the four individual, named checks.
//! - [`preflight`] -- assembles checks into `habitat install`'s and
//!   `habitat run`'s entry points, wiring in the audit sink.
//! - [`package_manager`] -- detects the host's dnf/apt package-manager
//!   family, used only by [`installer`].
//! - [`installer`] -- `habitat install`'s optional, opt-in auto-install
//!   step; the one part of the crate that mutates the host.

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
