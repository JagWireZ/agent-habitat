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
    // `crun`/`crun-krun` (Dnf family only): once `checks::crun_version`
    // has failed at all, the installed build is necessarily older than
    // the pinned, confirmed-good release it's now gated on
    // (`checks::MIN_CRUN_VERSION_FOR_PASST` -- see that constant's doc
    // comment for the real-hardware Fedora finding that raised it from
    // "new enough to accept krun.use_passt" to "this exact trusted
    // build"). So the fix here is always the pinned build via direct
    // URL, on every Dnf-family host, never a plain `dnf install
    // crun-krun` against the very repo package that just failed the
    // check -- there's no version left for that to plausibly fix.
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
        // `libkrunfw` fallback (Dnf family only): the primary attempt
        // above just tried `dnf install libkrunfw` and it didn't work --
        // on AlmaLinux 10 that's because EPEL has no `libkrunfw` package
        // under any name to resolve (confirmed real-hardware,
        // `tmp/wip/vm-launch-validation`), not a transient failure worth
        // retrying as-is. Fall back to a pinned, already-confirmed-working
        // binary from Fedora's own build system rather than leaving the
        // operator stuck on a package name that will never resolve here.
        // Rarely reached on a genuine Fedora host: `crun-krun` there
        // normally pulls in a matching `libkrunfw` automatically, so
        // `checks::libkrunfw` already passes and `install_missing` never
        // calls this at all -- unlike `crun-krun` above, there's no known
        // version-specific bug behind an already-present `libkrunfw`, so
        // this stays a plain "try the repo, fall back only if that
        // fails" rather than always bypassing the repo unconditionally.
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
/// release, or an operator's own manual install) by asking `rpm` what it
/// actually has on record -- the one authoritative "what's installed"
/// answer for this family (`package_manager::rpm_package_version`'s doc
/// comment). In practice this only matters when `checks::crun_version`
/// and `rpm`'s own record disagree (e.g. a from-source `krun` build
/// installed outside `rpm` entirely) -- `crun_version` already failing
/// is otherwise guaranteed to mean `rpm`'s version is too old as well,
/// since both now compare against the same pinned cutoff.
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
/// than one only for the `crun`+`crun-krun` fallback, which must install
/// both together -- see `package_manager::CRUN_FALLBACK_URL`'s doc
/// comment) and reports the outcome. Split out of [`attempt_one`] so
/// every fallback above can run this same logic again, against different
/// packages, without duplicating the command-construction and
/// audit-logging shape.
///
/// `packages` is what actually gets passed to `dnf`/`apt-get install`
/// (and is what the audit log's `running:`/`succeeded:` lines show, in
/// full -- never truncated, since that log is the accurate record of
/// what really ran as `sudo`). `display_name` is what the returned
/// [`InstallAttempt`] carries for the operator-facing checklist; the two
/// differ for the fallback cases, where `packages` are Koji URLs but the
/// checklist should still read as a plain package name.
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
    fn crun_version_installs_the_pinned_pair_when_rpm_shows_no_installed_version() {
        // No `rpm -q crun-krun` configured -- rpm_package_version can't
        // tell what's there, so this must not skip the install.
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
        // A host already on the pinned build (e.g. a second `habitat
        // install` run after the first one already fixed it) must not
        // reinstall the same rpm pair every time.
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
        // A host on something newer than the pinned build (a future
        // Fedora repo release, or an operator's own manual install) must
        // never be downgraded by this project's own pinned fallback.
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
        // The gap this whole mechanism exists for: real Fedora 44
        // hardware where `rpm -qa` shows `crun-krun-1.28-1.fc44` --
        // older than the pinned, confirmed-good build `checks::
        // crun_version` now requires.
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
