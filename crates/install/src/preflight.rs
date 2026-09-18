//! Assembles the individual checks in `checks.rs` into the two
//! operator-facing entry points:
//!
//! - [`run_install_checks`] -- what `habitat install` runs: host-OS gate,
//!   Podman, `krun`, `crun`-version, `passt`, `libkrunfw`. Verify-only.
//! - [`run_preflight`] -- what `habitat run` runs at the start of every
//!   session: the same checks plus KVM/hardware-virtualization.
//!
//! Both stop at the first failing check and log exactly one
//! `preflight-failure` / `install-failure` audit event naming that check
//! before returning. A clean run logs exactly one `preflight-pass` /
//! `install-pass` event instead -- a pass is not silence.

use crate::checks::{self, CheckFailure};
use crate::environment::Environment;
use habitat_audit::{AuditEvent, AuditSink, EventKind};
use std::fmt;

/// Returned by both entry points: the check that failed, already logged to
/// the audit sink by the time the caller sees it.
#[derive(Debug, Clone)]
pub struct PreflightError(pub CheckFailure);

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "preflight check failed: {}", self.0)
    }
}

impl std::error::Error for PreflightError {}

fn log_and_wrap(
    audit: &dyn AuditSink,
    event_kind: EventKind,
    failure: CheckFailure,
) -> PreflightError {
    let event = AuditEvent::now(
        event_kind,
        Some(failure.check.name()),
        failure.message.clone(),
    );
    // A failed audit write must not suppress the check failure itself.
    let _ = audit.record(&event);
    PreflightError(failure)
}

/// One check's outcome for status-report display, as opposed to
/// `run_install_checks`'s/`run_preflight`'s gating return value.
#[derive(Debug, Clone)]
pub struct CheckStatus {
    pub check: checks::CheckId,
    pub result: checks::CheckResult,
}

impl CheckStatus {
    pub fn passed(&self) -> bool {
        self.result.is_ok()
    }
}

/// Runs every check `habitat install` cares about and reports a status for
/// each, rather than stopping at the first failure, so an operator can see
/// every prerequisite's state in one pass. Read-only and unaudited --
/// [`run_install_checks`] owns the single-audited-failure-per-run gate.
///
/// The host-OS gate is the one exception to "run everything": if it
/// fails, every other check's assumptions are meaningless, so they're
/// left unreported.
///
/// `betterleaks` is included unconditionally here (unlike
/// [`preflight_report`]'s gated inclusion) since `habitat install` has no
/// project in scope to read a `secrets_scan.content` toggle from, and the
/// default is enabled. It stays out of [`run_install_checks`]'s pass/fail
/// gate though, since a project can still opt out.
pub fn install_report<E: Environment>(env: &E) -> Vec<CheckStatus> {
    let host_os = checks::host_os(env);
    let host_os_failed = host_os.is_err();
    let mut statuses = vec![CheckStatus {
        check: checks::CheckId::HostOs,
        result: host_os,
    }];
    if host_os_failed {
        return statuses;
    }
    statuses.push(CheckStatus {
        check: checks::CheckId::Podman,
        result: checks::podman(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::KrunRuntime,
        result: checks::krun_runtime(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::CrunVersion,
        result: checks::crun_version(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::Passt,
        result: checks::passt(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::Libkrunfw,
        result: checks::libkrunfw(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::Betterleaks,
        result: checks::betterleaks(env),
    });
    statuses
}

/// The same idea as [`install_report`], but over the checks `habitat run`'s
/// preflight uses (adds the `kvm` check). `betterleaks` only appears when
/// `secrets_scan_content_enabled` is true.
pub fn preflight_report<E: Environment>(
    env: &E,
    secrets_scan_content_enabled: bool,
) -> Vec<CheckStatus> {
    let host_os = checks::host_os(env);
    let host_os_failed = host_os.is_err();
    let mut statuses = vec![CheckStatus {
        check: checks::CheckId::HostOs,
        result: host_os,
    }];
    if host_os_failed {
        return statuses;
    }
    statuses.push(CheckStatus {
        check: checks::CheckId::Kvm,
        result: checks::kvm(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::Podman,
        result: checks::podman(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::KrunRuntime,
        result: checks::krun_runtime(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::CrunVersion,
        result: checks::crun_version(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::Passt,
        result: checks::passt(env),
    });
    statuses.push(CheckStatus {
        check: checks::CheckId::Libkrunfw,
        result: checks::libkrunfw(env),
    });
    if secrets_scan_content_enabled {
        statuses.push(CheckStatus {
            check: checks::CheckId::Betterleaks,
            result: checks::betterleaks(env),
        });
    }
    statuses
}

/// `habitat install`'s verification sequence. The host-OS gate runs first
/// and pre-empts checks that would be meaningless on a refused host.
pub fn run_install_checks<E: Environment>(
    env: &E,
    audit: &dyn AuditSink,
) -> Result<(), PreflightError> {
    checks::host_os(env).map_err(|f| log_and_wrap(audit, EventKind::InstallFailure, f))?;
    checks::podman(env).map_err(|f| log_and_wrap(audit, EventKind::InstallFailure, f))?;
    checks::krun_runtime(env).map_err(|f| log_and_wrap(audit, EventKind::InstallFailure, f))?;
    checks::crun_version(env).map_err(|f| log_and_wrap(audit, EventKind::InstallFailure, f))?;
    checks::passt(env).map_err(|f| log_and_wrap(audit, EventKind::InstallFailure, f))?;
    checks::libkrunfw(env).map_err(|f| log_and_wrap(audit, EventKind::InstallFailure, f))?;
    let _ = audit.record(&AuditEvent::now(EventKind::InstallPass, None, "install checks passed"));
    Ok(())
}

/// `habitat run`'s preflight subroutine, executed at the start of every
/// session before any disk-build/VM-launch logic.
///
/// `secrets_scan_content_enabled` reflects the project's checked-in
/// config (default enabled). When true, `betterleaks` is checked for on
/// `PATH` in this same pass; when false, the check is skipped entirely.
pub fn run_preflight<E: Environment>(
    env: &E,
    audit: &dyn AuditSink,
    secrets_scan_content_enabled: bool,
) -> Result<(), PreflightError> {
    checks::host_os(env).map_err(|f| log_and_wrap(audit, EventKind::PreflightFailure, f))?;
    checks::kvm(env).map_err(|f| log_and_wrap(audit, EventKind::PreflightFailure, f))?;
    checks::podman(env).map_err(|f| log_and_wrap(audit, EventKind::PreflightFailure, f))?;
    checks::krun_runtime(env).map_err(|f| log_and_wrap(audit, EventKind::PreflightFailure, f))?;
    checks::crun_version(env).map_err(|f| log_and_wrap(audit, EventKind::PreflightFailure, f))?;
    checks::passt(env).map_err(|f| log_and_wrap(audit, EventKind::PreflightFailure, f))?;
    checks::libkrunfw(env).map_err(|f| log_and_wrap(audit, EventKind::PreflightFailure, f))?;
    if secrets_scan_content_enabled {
        checks::betterleaks(env)
            .map_err(|f| log_and_wrap(audit, EventKind::PreflightFailure, f))?;
    }
    let _ = audit.record(&AuditEvent::now(EventKind::PreflightPass, None, "preflight passed"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::testing::FakeEnvironment;
    use habitat_audit::MemoryAuditSink;

    #[test]
    fn install_checks_stop_at_first_failure_and_log_it() {
        let env = FakeEnvironment {
            os_family: "windows".to_string(),
            ..Default::default()
        };
        let audit = MemoryAuditSink::default();
        let err = run_install_checks(&env, &audit).unwrap_err();
        assert_eq!(err.0.check.name(), "host-os");

        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.tag(), "install-failure");
        assert_eq!(events[0].check.as_deref(), Some("host-os"));
    }

    #[test]
    fn install_checks_pass_end_to_end_when_everything_is_present() {
        let env = FakeEnvironment::linux()
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n")
            .with_command_ok("passt --version", "passt 0.0~git\n")
            .with_command_ok("ldconfig -p", "\tlibkrunfw.so.5 => /lib64/libkrunfw.so.5\n");
        let audit = MemoryAuditSink::default();
        assert!(run_install_checks(&env, &audit).is_ok());
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1, "a clean run logs its pass, not silence");
        assert_eq!(events[0].kind.tag(), "install-pass");
    }

    #[test]
    fn install_checks_fail_closed_when_crun_version_is_too_old_even_with_krun_present() {
        let env = FakeEnvironment::linux()
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.27\ncommit: abc\n");
        let audit = MemoryAuditSink::default();
        let err = run_install_checks(&env, &audit).unwrap_err();
        assert_eq!(err.0.check.name(), "crun-version");
    }

    #[test]
    fn install_checks_fail_closed_when_passt_is_missing_even_with_krun_present() {
        let env = FakeEnvironment::linux()
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n");
        // Deliberately no `passt --version` command configured on the fake.
        let audit = MemoryAuditSink::default();
        let err = run_install_checks(&env, &audit).unwrap_err();
        assert_eq!(err.0.check.name(), "passt");
    }

    #[test]
    fn install_checks_fail_closed_when_libkrunfw_is_missing_even_with_krun_present() {
        let env = FakeEnvironment::linux()
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n")
            .with_command_ok("passt --version", "passt 0.0~git\n");
        let audit = MemoryAuditSink::default();
        let err = run_install_checks(&env, &audit).unwrap_err();
        assert_eq!(err.0.check.name(), "libkrunfw");
    }

    #[test]
    fn preflight_passes_end_to_end_when_everything_is_present() {
        let env = FakeEnvironment::linux()
            .with_existing_path("/dev/kvm")
            .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc")
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n")
            .with_command_ok("passt --version", "passt 0.0~git\n")
            .with_command_ok("ldconfig -p", "\tlibkrunfw.so.5 => /lib64/libkrunfw.so.5\n");
        let audit = MemoryAuditSink::default();
        assert!(run_preflight(&env, &audit, false).is_ok());
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1, "a clean run logs its pass, not silence");
        assert_eq!(events[0].kind.tag(), "preflight-pass");
    }

    #[test]
    fn preflight_fails_closed_when_crun_version_is_too_old_even_with_krun_present() {
        let env = FakeEnvironment::linux()
            .with_existing_path("/dev/kvm")
            .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc")
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.27\ncommit: abc\n");
        let audit = MemoryAuditSink::default();
        let err = run_preflight(&env, &audit, false).unwrap_err();
        assert_eq!(err.0.check.name(), "crun-version");
    }

    #[test]
    fn preflight_fails_closed_when_passt_is_missing_even_with_krun_present() {
        let env = FakeEnvironment::linux()
            .with_existing_path("/dev/kvm")
            .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc")
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n");
        // Deliberately no `passt --version` command configured on the fake.
        let audit = MemoryAuditSink::default();
        let err = run_preflight(&env, &audit, false).unwrap_err();
        assert_eq!(err.0.check.name(), "passt");
    }

    #[test]
    fn preflight_fails_closed_when_libkrunfw_is_missing_even_with_krun_present() {
        let env = FakeEnvironment::linux()
            .with_existing_path("/dev/kvm")
            .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc")
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n")
            .with_command_ok("passt --version", "passt 0.0~git\n");
        // Deliberately no `ldconfig -p` command configured on the fake.
        let audit = MemoryAuditSink::default();
        let err = run_preflight(&env, &audit, false).unwrap_err();
        assert_eq!(err.0.check.name(), "libkrunfw");
    }

    #[test]
    fn preflight_checks_betterleaks_only_when_content_scanning_is_enabled() {
        let env = FakeEnvironment::linux()
            .with_existing_path("/dev/kvm")
            .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc")
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n")
            .with_command_ok("passt --version", "passt 0.0~git\n")
            .with_command_ok("ldconfig -p", "\tlibkrunfw.so.5 => /lib64/libkrunfw.so.5\n");
        // Deliberately no `betterleaks` command configured on the fake.

        let audit = MemoryAuditSink::default();
        assert!(
            run_preflight(&env, &audit, false).is_ok(),
            "disabled content scanning must not require betterleaks at all"
        );

        let audit = MemoryAuditSink::default();
        let err = run_preflight(&env, &audit, true)
            .expect_err("enabled content scanning without betterleaks installed must fail closed");
        assert_eq!(err.0.check.name(), "betterleaks");
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.tag(), "preflight-failure");
        assert_eq!(events[0].check.as_deref(), Some("betterleaks"));
    }

    #[test]
    fn install_report_lists_every_check_even_after_a_failure() {
        let env = FakeEnvironment::linux();
        let report = install_report(&env);
        assert_eq!(
            report.len(),
            7,
            "host-os, podman, krun-runtime, crun-version, passt, libkrunfw, betterleaks"
        );
        assert_eq!(report[0].check.name(), "host-os");
        assert!(report[0].passed());
        assert_eq!(report[1].check.name(), "podman");
        assert!(!report[1].passed());
        assert_eq!(report[2].check.name(), "krun-runtime");
        assert!(!report[2].passed());
        assert_eq!(report[3].check.name(), "crun-version");
        assert!(!report[3].passed());
        assert_eq!(report[4].check.name(), "passt");
        assert!(!report[4].passed());
        assert_eq!(report[5].check.name(), "libkrunfw");
        assert!(!report[5].passed());
        assert_eq!(report[6].check.name(), "betterleaks");
        assert!(!report[6].passed());
    }

    #[test]
    fn install_report_stops_at_host_os_when_not_linux() {
        let env = FakeEnvironment {
            os_family: "windows".to_string(),
            ..Default::default()
        };
        let report = install_report(&env);
        assert_eq!(
            report.len(),
            1,
            "no other check's assumptions hold on a refused host"
        );
        assert!(!report[0].passed());
    }

    #[test]
    fn install_report_all_pass_when_everything_present() {
        let env = FakeEnvironment::linux()
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n")
            .with_command_ok("passt --version", "passt 0.0~git\n")
            .with_command_ok("ldconfig -p", "\tlibkrunfw.so.5 => /lib64/libkrunfw.so.5\n")
            .with_command_ok("betterleaks --version", "betterleaks 0.4.0");
        let report = install_report(&env);
        assert!(report.iter().all(CheckStatus::passed));
    }

    #[test]
    fn preflight_report_includes_kvm() {
        let env = FakeEnvironment::linux();
        let report = preflight_report(&env, false);
        assert_eq!(
            report.len(),
            7,
            "host-os, kvm, podman, krun-runtime, crun-version, passt, libkrunfw"
        );
        assert_eq!(report[1].check.name(), "kvm");
        assert!(!report[1].passed());
        assert_eq!(report[5].check.name(), "passt");
        assert_eq!(report[6].check.name(), "libkrunfw");
    }

    #[test]
    fn preflight_report_includes_betterleaks_only_when_content_scanning_enabled() {
        let env = FakeEnvironment::linux();
        let without = preflight_report(&env, false);
        assert_eq!(
            without.len(),
            7,
            "host-os, kvm, podman, krun-runtime, crun-version, passt, libkrunfw"
        );
        assert!(!without.iter().any(|s| s.check.name() == "betterleaks"));

        let with = preflight_report(&env, true);
        assert_eq!(with.len(), 8, "+ betterleaks");
        assert_eq!(with[7].check.name(), "betterleaks");
    }

    /// Audit-sink failures (e.g. an unwritable log path) must not soften
    /// or suppress the underlying check failure.
    #[test]
    fn audit_sink_failure_does_not_mask_check_failure() {
        struct FailingSink;
        impl AuditSink for FailingSink {
            fn record(&self, _event: &AuditEvent) -> std::io::Result<()> {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "disk full"))
            }
        }
        let env = FakeEnvironment {
            os_family: "windows".to_string(),
            ..Default::default()
        };
        let err = run_install_checks(&env, &FailingSink).unwrap_err();
        assert_eq!(err.0.check.name(), "host-os");
    }
}
