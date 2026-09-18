//! `habitat install`'s optional auto-install step.
//!
//! The one place in the crate that mutates the host; runs only after the
//! CLI crate has gotten the operator's explicit confirmation.

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
/// with inherited stdio so the operator sees and can respond to `sudo`'s
/// password prompt.
///
/// Every attempt (not just failures) is logged to `audit` as a distinct
/// `install-action` event.
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
    // Dnf-only: a failed crun_version check means the installed build is
    // older than MIN_CRUN_VERSION_FOR_PASST, so always install the pinned
    // build via direct URL rather than `dnf install crun-krun` against
    // the same repo package that just failed.
    if family == PackageFamily::Dnf && check == CheckId::CrunVersion {
        return install_pinned_unless_already_current(
            env,
            audit,
            family,
            check,
            "crun-krun",
            package_manager::CRUN_PINNED_VERSION,
            &[
                package_manager::CRUN_FALLBACK_URL,
                package_manager::CRUN_KRUN_FALLBACK_URL,
            ],
        );
    }

    let Some(package) = package_manager::package_for(check, family) else {
        return InstallAttempt::NotAvailable { check };
    };
    let primary = run_package_command(env, audit, check, family, &[package], package);
    if matches!(primary, InstallAttempt::Succeeded { .. }) {
        return primary;
    }

    match (check, family) {
        // Dnf libkrunfw fallback: EPEL (e.g. AlmaLinux 10) has no
        // libkrunfw package under any name, so fall back to a pinned
        // binary from Fedora's build system rather than leaving the
        // operator stuck. Rarely reached on real Fedora, where crun-krun
        // pulls in a matching libkrunfw automatically.
        (CheckId::Libkrunfw, PackageFamily::Dnf) => {
            log(
                audit,
                check,
                format!(
                    "`dnf install libkrunfw` didn't resolve -- falling back to {}",
                    package_manager::LIBKRUNFW_FALLBACK_URL
                ),
            );
            run_package_command(
                env,
                audit,
                check,
                family,
                &[package_manager::LIBKRUNFW_FALLBACK_URL],
                "libkrunfw",
            )
        }
        _ => primary,
    }
}

/// `crun-krun`'s pinned Dnf-family install: never downgrade a host
/// that's already at or past `pinned_version` (a future Fedora repo
/// release, or an operator's own manual install) -- checked by asking
/// `rpm` what it actually has installed.
fn install_pinned_unless_already_current<E: Environment>(
    env: &E,
    audit: &dyn AuditSink,
    family: PackageFamily,
    check: CheckId,
    rpm_package: &str,
    pinned_version: (u32, u32, u32),
    pinned_urls: &[&str],
) -> InstallAttempt {
    if let Some(installed) = package_manager::rpm_package_version(env, rpm_package) {
        if installed >= pinned_version {
            log(
                audit,
                check,
                format!(
                    "installed {rpm_package} {}.{}.{} is already >= the pinned {}.{}.{} -- \
                     leaving it alone",
                    installed.0,
                    installed.1,
                    installed.2,
                    pinned_version.0,
                    pinned_version.1,
                    pinned_version.2,
                ),
            );
            return InstallAttempt::Succeeded {
                check,
                package: rpm_package.to_string(),
            };
        }
    }
    run_package_command(env, audit, check, family, pinned_urls, rpm_package)
}

/// Runs one `dnf`/`apt-get install` against one or more `packages` (more
/// than one only for the `crun`+`crun-krun` fallback) and reports the
/// outcome.
///
/// `packages` is what actually gets passed to the install command and
/// logged in full. `display_name` is what the returned [`InstallAttempt`]
/// carries for the operator-facing checklist -- differs from `packages`
/// in the fallback cases, where `packages` are Koji URLs.
fn run_package_command<E: Environment>(
    env: &E,
    audit: &dyn AuditSink,
    check: CheckId,
    family: PackageFamily,
    packages: &[&str],
    display_name: &str,
) -> InstallAttempt {
    let (program, args) = package_manager::install_command(family, packages);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let cmd_line = format!("{program} {}", arg_refs.join(" "));
    let packages_joined = packages.join(" ");

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
                package: packages_joined,
            }
        }
        Err(e) => {
            log(audit, check, format!("failed to start: {cmd_line} ({e})"));
            InstallAttempt::Failed {
                check,
                package: packages_joined,
            }
        }
    }
}

fn log(audit: &dyn AuditSink, check: CheckId, message: String) {
    let event = AuditEvent::now(EventKind::InstallAction, Some(check.name()), message);
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
        assert_eq!(
            *env.inherited_invocations.borrow(),
            vec!["sudo apt-get install -y podman".to_string()]
        );
    }

    #[test]
    fn libkrunfw_falls_back_to_the_pinned_url_when_the_named_package_is_unavailable() {
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
    fn crun_version_installs_the_pinned_pair_when_rpm_shows_no_installed_version() {
        let fallback_cmd = format!(
            "sudo dnf install -y {} {}",
            package_manager::CRUN_FALLBACK_URL,
            package_manager::CRUN_KRUN_FALLBACK_URL
        );
        let env = FakeEnvironment::linux().with_inherited_command_ok(&fallback_cmd);
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Dnf, &[CheckId::CrunVersion]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::Succeeded {
                check: CheckId::CrunVersion,
                package: "crun-krun".to_string(),
            }]
        );
        assert_eq!(*env.inherited_invocations.borrow(), vec![fallback_cmd]);
    }

    #[test]
    fn crun_version_skips_the_pinned_install_when_rpm_already_shows_that_version() {
        let env = FakeEnvironment::linux()
            .with_command_ok("rpm -q --queryformat %{VERSION}\\n crun-krun", "1.29.1\n");
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Dnf, &[CheckId::CrunVersion]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::Succeeded {
                check: CheckId::CrunVersion,
                package: "crun-krun".to_string(),
            }]
        );
        assert!(
            env.inherited_invocations.borrow().is_empty(),
            "no dnf install should run when the host is already at the pinned version"
        );
    }

    #[test]
    fn crun_version_skips_the_pinned_install_when_rpm_already_shows_something_newer() {
        let env = FakeEnvironment::linux()
            .with_command_ok("rpm -q --queryformat %{VERSION}\\n crun-krun", "1.30.0\n");
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Dnf, &[CheckId::CrunVersion]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::Succeeded {
                check: CheckId::CrunVersion,
                package: "crun-krun".to_string(),
            }]
        );
        assert!(env.inherited_invocations.borrow().is_empty());
    }

    #[test]
    fn crun_version_still_installs_the_pinned_pair_when_rpm_shows_an_older_version() {
        let fallback_cmd = format!(
            "sudo dnf install -y {} {}",
            package_manager::CRUN_FALLBACK_URL,
            package_manager::CRUN_KRUN_FALLBACK_URL
        );
        let env = FakeEnvironment::linux()
            .with_command_ok("rpm -q --queryformat %{VERSION}\\n crun-krun", "1.28\n")
            .with_inherited_command_ok(&fallback_cmd);
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Dnf, &[CheckId::CrunVersion]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::Succeeded {
                check: CheckId::CrunVersion,
                package: "crun-krun".to_string(),
            }]
        );
        assert_eq!(*env.inherited_invocations.borrow(), vec![fallback_cmd]);
    }

    #[test]
    fn crun_version_reports_failed_when_the_pinned_install_fails() {
        let fallback_cmd = format!(
            "sudo dnf install -y {} {}",
            package_manager::CRUN_FALLBACK_URL,
            package_manager::CRUN_KRUN_FALLBACK_URL
        );
        let env = FakeEnvironment::linux().with_inherited_command_failure(&fallback_cmd);
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Dnf, &[CheckId::CrunVersion]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::Failed {
                check: CheckId::CrunVersion,
                package: format!(
                    "{} {}",
                    package_manager::CRUN_FALLBACK_URL,
                    package_manager::CRUN_KRUN_FALLBACK_URL
                ),
            }]
        );
    }

    #[test]
    fn crun_version_never_falls_back_on_the_apt_family() {
        let env = FakeEnvironment::linux();
        let audit = MemoryAuditSink::default();

        let attempts = install_missing(&env, &audit, PackageFamily::Apt, &[CheckId::CrunVersion]);

        assert_eq!(
            attempts,
            vec![InstallAttempt::NotAvailable {
                check: CheckId::CrunVersion
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
