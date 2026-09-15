//! `habitat install`'s optional auto-install step.
//!
//! `checks.rs`/`preflight.rs` stay verify-only, as documented there; this
//! module is the one place in the crate that actually mutates the host,
//! and it only runs when the operator has explicitly asked it to (the
//! "would you like to install the missing pieces?" confirmation lives in
//! the CLI crate, which owns all operator-facing I/O -- this module just
//! knows how to run the commands once told to, and reports what
//! happened).

use crate::checks::CheckId;
use crate::environment::Environment;
use crate::package_manager::{self, PackageFamily};
use habitat_audit::{AuditEvent, AuditSink, EventKind};

/// One failed check's auto-install attempt outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallAttempt {
    /// The install command ran and exited successfully.
    Succeeded { check: CheckId, package: String },
    /// The install command ran but exited non-zero, or couldn't even be
    /// started (e.g. `sudo` itself missing) -- either way, the check
    /// should be assumed still failing until re-verified.
    Failed { check: CheckId, package: String },
    /// Nothing to run: this check has no package-manager fix on this
    /// family (e.g. `krun-runtime` on the apt family isn't packaged yet;
    /// `host-os`/`kvm` have no package-manager fix on any family).
    NotAvailable { check: CheckId },
}

/// Attempts to auto-install every check in `checks` that has a real
/// package-manager fix on `family`, one at a time and in order, each run
/// with inherited stdio so the operator sees -- and can respond to --
/// `sudo`'s password prompt and the package manager's own output live.
///
/// Every attempt (not just failures) is logged to `audit` as a distinct
/// `install-action` event: running a privileged command on the
/// operator's behalf is itself worth a durable record, independent of
/// whether it succeeded (mirrors `preflight.rs`'s failure logging, which
/// also never lets a sink error suppress the underlying outcome).
pub fn install_missing<E: Environment>(
    env: &E,
    audit: &dyn AuditSink,
    family: PackageFamily,
    checks: &[CheckId],
) -> Vec<InstallAttempt> {
    checks
        .iter()
        .map(|&check| attempt_one(env, audit, family, check))
        .collect()
}

fn attempt_one<E: Environment>(
    env: &E,
    audit: &dyn AuditSink,
    family: PackageFamily,
    check: CheckId,
) -> InstallAttempt {
    let Some(package) = package_manager::package_for(check, family) else {
        return InstallAttempt::NotAvailable { check };
    };
    let primary = run_package_command(env, audit, check, family, package, package);
    if matches!(primary, InstallAttempt::Succeeded { .. }) {
        return primary;
    }

    // `libkrunfw` fallback (Dnf family only): the primary attempt above
    // just tried `dnf install libkrunfw` and it didn't work -- on
    // AlmaLinux 10 today that's because EPEL has no `libkrunfw` package
    // under any name to resolve (confirmed real-hardware,
    // `tmp/wip/vm-launch-validation`), not a transient failure worth
    // retrying as-is. Fall back to a pinned, already-confirmed-working
    // binary from Fedora's own build system rather than leaving the
    // operator stuck on a package name that will never resolve here.
    // Never reached on a genuine Fedora host: `crun-krun` there already
    // pulls in a matching `libkrunfw`, so `checks::libkrunfw` passes and
    // `install_missing` never calls this function for this check at all.
    //
    // `display_name` stays `"libkrunfw"` here even though the actual `dnf
    // install` argument is the fallback URL: the operator-facing "what
    // got installed" line should read like every other check's (a
    // package name), not spill a Koji URL into the checklist -- the full
    // URL is still there in the audit log below, not hidden.
    if check == CheckId::Libkrunfw && family == PackageFamily::Dnf {
        log(
            audit,
            check,
            format!(
                "`dnf install libkrunfw` didn't resolve -- falling back to {}",
                package_manager::LIBKRUNFW_FALLBACK_URL
            ),
        );
        return run_package_command(
            env,
            audit,
            check,
            family,
            package_manager::LIBKRUNFW_FALLBACK_URL,
            "libkrunfw",
        );
    }

    primary
}

/// Runs one `dnf`/`apt-get install` (or, for the `libkrunfw` fallback, a
/// direct URL `dnf install` accepts the same way) and reports the
/// outcome. Split out of [`attempt_one`] so the `libkrunfw` fallback
/// above can run this same logic a second time, against a different
/// `package` argument, without duplicating the command-construction and
/// audit-logging shape.
///
/// `package` is what actually gets passed to `dnf`/`apt-get install`
/// (and is what the audit log's `running:`/`succeeded:` lines show, in
/// full -- never truncated, since that log is the accurate record of
/// what really ran as `sudo`). `display_name` is what the returned
/// [`InstallAttempt`] carries for the operator-facing checklist; the two
/// differ only for the `libkrunfw` fallback, where `package` is a Koji
/// URL but the checklist should still read as a plain package name.
fn run_package_command<E: Environment>(
    env: &E,
    audit: &dyn AuditSink,
    check: CheckId,
    family: PackageFamily,
    package: &str,
    display_name: &str,
) -> InstallAttempt {
    let (program, args) = package_manager::install_command(family, package);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let cmd_line = format!("{program} {}", arg_refs.join(" "));

    log(audit, check, format!("running: {cmd_line}"));
    match env.run_command_inherited(program, &arg_refs) {
        Ok(true) => {
            log(audit, check, format!("succeeded: {cmd_line}"));
            InstallAttempt::Succeeded {
                check,
                package: display_name.to_string(),
            }
        }
        Ok(false) => {
            log(audit, check, format!("failed (non-zero exit): {cmd_line}"));
            InstallAttempt::Failed {
                check,
                package: package.to_string(),
            }
        }
        Err(e) => {
            log(audit, check, format!("failed to start: {cmd_line} ({e})"));
            InstallAttempt::Failed {
                check,
                package: package.to_string(),
            }
        }
    }
}

fn log(audit: &dyn AuditSink, check: CheckId, message: String) {
    let event = AuditEvent::now(EventKind::InstallAction, Some(check.name()), message);
    // Same reasoning as `preflight.rs::log_and_wrap`: an audit-sink
    // failure (e.g. disk full) must never suppress or alter the outcome
    // being reported to the operator.
    let _ = audit.record(&event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::testing::FakeEnvironment;
    use habitat_audit::MemoryAuditSink;

    #[test]
    fn installs_podman_and_krun_runtime_on_dnf_family() {
        let env = FakeEnvironment::linux()
            .with_inherited_command_ok("sudo dnf install -y podman")
            .with_inherited_command_ok("sudo dnf install -y crun-krun");
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(
            &env,
            &audit,
            PackageFamily::Dnf,
            &[CheckId::Podman, CheckId::KrunRuntime],
        );

        assert_eq!(
            attempts,
            vec![
                InstallAttempt::Succeeded {
                    check: CheckId::Podman,
                    package: "podman".to_string()
                },
                InstallAttempt::Succeeded {
                    check: CheckId::KrunRuntime,
                    package: "crun-krun".to_string()
                },
            ]
        );
        assert_eq!(
            *env.inherited_invocations.borrow(),
            vec![
                "sudo dnf install -y podman".to_string(),
                "sudo dnf install -y crun-krun".to_string(),
            ]
        );

        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 4, "one 'running' + one 'succeeded' per check");
        assert!(events.iter().all(|e| e.kind.tag() == "install-action"));
    }

    #[test]
    fn reports_krun_runtime_not_available_on_apt_family_without_running_anything() {
        let env =
            FakeEnvironment::linux().with_inherited_command_ok("sudo apt-get install -y podman");
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(
            &env,
            &audit,
            PackageFamily::Apt,
            &[CheckId::Podman, CheckId::KrunRuntime],
        );

        assert_eq!(
            attempts,
            vec![
                InstallAttempt::Succeeded {
                    check: CheckId::Podman,
                    package: "podman".to_string()
                },
                InstallAttempt::NotAvailable {
                    check: CheckId::KrunRuntime
                },
            ]
        );
        // krun-runtime never even reached run_command_inherited.
        assert_eq!(
            *env.inherited_invocations.borrow(),
            vec!["sudo apt-get install -y podman".to_string()]
        );
    }

    #[test]
    fn libkrunfw_falls_back_to_the_pinned_url_when_the_named_package_is_unavailable() {
        // Mirrors real AlmaLinux 10 hardware: `dnf install libkrunfw`
        // fails outright (no such package in EPEL), so the fallback URL
        // must be the one that actually gets attempted second.
        let fallback_cmd = format!(
            "sudo dnf install -y {}",
            package_manager::LIBKRUNFW_FALLBACK_URL
        );
        let env = FakeEnvironment::linux()
            .with_inherited_command_failure("sudo dnf install -y libkrunfw")
            .with_inherited_command_ok(&fallback_cmd);
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Dnf, &[CheckId::Libkrunfw]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::Succeeded {
                check: CheckId::Libkrunfw,
                package: "libkrunfw".to_string(),
            }]
        );
        assert_eq!(
            *env.inherited_invocations.borrow(),
            vec!["sudo dnf install -y libkrunfw".to_string(), fallback_cmd]
        );
    }

    #[test]
    fn libkrunfw_reports_failed_when_both_the_named_package_and_the_fallback_fail() {
        let fallback_cmd = format!(
            "sudo dnf install -y {}",
            package_manager::LIBKRUNFW_FALLBACK_URL
        );
        let env = FakeEnvironment::linux()
            .with_inherited_command_failure("sudo dnf install -y libkrunfw")
            .with_inherited_command_failure(&fallback_cmd);
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Dnf, &[CheckId::Libkrunfw]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::Failed {
                check: CheckId::Libkrunfw,
                package: package_manager::LIBKRUNFW_FALLBACK_URL.to_string(),
            }]
        );
    }

    #[test]
    fn libkrunfw_never_falls_back_on_the_apt_family() {
        // No `package_for` mapping at all on Apt, so this must report
        // `NotAvailable` without running anything -- the same "None,
        // never a guess" posture as `KrunRuntime` on Apt.
        let env = FakeEnvironment::linux();
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Apt, &[CheckId::Libkrunfw]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::NotAvailable {
                check: CheckId::Libkrunfw
            }]
        );
        assert!(env.inherited_invocations.borrow().is_empty());
    }

    #[test]
    fn a_failed_install_command_is_reported_and_logged_without_masking() {
        let env =
            FakeEnvironment::linux().with_inherited_command_failure("sudo dnf install -y podman");
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Dnf, &[CheckId::Podman]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::Failed {
                check: CheckId::Podman,
                package: "podman".to_string()
            }]
        );
        let events = audit.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| e.message.contains("failed (non-zero exit)")));
    }
}
