//! Assembles the individual checks in `checks.rs` into the two
//! operator-facing entry points:
//!
//! - [`run_install_checks`] -- what `habitat install` runs: host-OS gate,
//!   Podman, the `krun` runtime, whether that `crun`/`krun` build is new
//!   enough to hand off to real `passt` networking (`checks::
//!   crun_version`), whether `passt` itself is actually installed
//!   (`checks::passt` -- a distinct requirement from the version check
//!   above, see that function's doc comment), and `libkrunfw` (the shared
//!   library `krun` needs to actually boot a microVM, checked separately
//!   from the `krun` binary itself -- see `checks::libkrunfw`'s doc
//!   comment for why). Verify-only, no mutation.
//! - [`run_preflight`] -- what `habitat run` runs at the start of every
//!   session: host-OS gate, KVM/hardware-virtualization, then the same
//!   Podman, `krun`-runtime, `crun`-version, `passt`, and `libkrunfw`
//!   checks `habitat install` uses (one implementation, reused -- not
//!   re-derived).
//!
//! Both stop at the first failing check (fail-closed and deterministic:
//! an operator fixes one problem at a time rather than triaging a wall of
//! failures that may be masking each other) and log exactly one
//! `preflight-failure` / `install-failure` audit event naming that check
//! before returning.

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
    // The audit sink itself can fail (e.g. disk full, unwritable path).
    // That must never suppress or soften the check failure it was trying
    // to log -- the check result already fails closed regardless of
    // whether the log write succeeded.
    let _ = audit.record(&event);
    PreflightError(failure)
}

/// One check's outcome for status-report display (`habitat install`'s and
/// `habitat run`'s checklist), as opposed to `run_install_checks`'s /
/// `run_preflight`'s gating return value. Carries the same [`CheckResult`]
/// so a caller can render exactly the same failure message the gate would
/// report -- no separate wording to keep in sync.
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
/// each, rather than stopping at the first failure -- so an operator can
/// see every prerequisite's state in one pass ("this is present, this
/// isn't") instead of fixing them one at a time through repeated runs.
///
/// This is a read-only, unaudited companion to [`run_install_checks`]: it
/// logs nothing (the single-audited-failure-per-run invariant stays
/// [`run_install_checks`]'s job) and never mutates anything, same as the
/// checks themselves.
///
/// The host-OS gate is the one exception to "run everything": if it
/// fails, every other check's assumptions (about *this* host being Linux)
/// are meaningless, so they're left unreported rather than actually run.
///
/// `betterleaks` is included unconditionally here, unlike
/// [`preflight_report`]'s `secrets_scan_content_enabled`-gated inclusion:
/// `habitat install` runs with no project in scope (there's no
/// `sandbox.yaml` to read a `secrets_scan.content` toggle from), and the
/// project-level default for that toggle is enabled. Surfacing it here
/// lets an operator install it up front, alongside Podman/krun-runtime,
/// instead of only discovering it's missing the first time `habitat run`
/// hits a project that wants it. It stays out of [`run_install_checks`]'s
/// pass/fail gate, though: a project that has genuinely opted out via
/// `secrets_scan.content: disabled` shouldn't make `habitat install`
/// report an unfinished setup over a binary that project doesn't need.
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
/// preflight uses (adds the `kvm` check `habitat install` doesn't run).
///
/// `secrets_scan_content_enabled` mirrors `run_preflight`'s parameter of
/// the same name: the `betterleaks` check only appears in the report when
/// the project's checked-in config has `secrets_scan.content` enabled
/// (the default) -- a project that has explicitly opted out shouldn't see
/// a checklist item for a binary it doesn't need.
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

/// `habitat install`'s verification sequence. Order matters: the host-OS
/// gate is cheapest and most fundamental, so it runs first and pre-empts
/// checks that would be meaningless on a refused host.
/// `libkrunfw`, `crun-version`, and `passt` are included here as hard,
/// unconditional requirements (unlike `betterleaks` below) -- they're
/// real host-level prerequisites for any session to launch with real
/// networking at all, never something a project can opt out of, so they
/// belong in the same pass/fail gate as Podman/`krun-runtime`.
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
    Ok(())
}

/// `habitat run`'s preflight subroutine, executed at the start of every
/// session before any disk-build/VM-launch logic (Phases 2/3 hook in
/// after this returns `Ok`, never around it).
///
/// `secrets_scan_content_enabled` reflects the project's checked-in
/// config (`habitat_policy::config::ProjectConfig::secrets_scan.content`,
/// default enabled). When true, the `betterleaks` binary is checked for
/// on `PATH` in this same pass, right alongside the KVM/Podman/krun-
/// runtime checks -- a project that wants content-based secrets scanning
/// must not be able to silently end up without it because the binary
/// isn't installed; that's a hard preflight failure, same fail-closed
/// posture as every other check here (AGENTS.md Section 2 invariant 11).
/// When false (the project explicitly opted out), the check is skipped
/// entirely rather than run-and-ignored.
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
        assert!(audit.events.lock().unwrap().is_empty());
    }

    #[test]
    fn install_checks_fail_closed_when_crun_version_is_too_old_even_with_krun_present() {
        // The exact real-hardware finding this check exists for: `krun
        // --version` succeeding says nothing about whether it's new
        // enough for real passt networking (AlmaLinux 10's own
        // crun-krun-1.27-2.el10_2 predates the 1.27.1 cutoff).
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
        // `crun_version` passing says nothing about whether `passt`
        // itself is installed -- it only checks crun-krun's ability to
        // hand off to passt, not passt's own presence.
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
        // The exact real-hardware finding this check exists for: `krun
        // --version` alone must not be read as "a session can launch."
        let env = FakeEnvironment::linux()
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...")
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n")
            .with_command_ok("passt --version", "passt 0.0~git\n");
        // Deliberately no `ldconfig -p` command configured on the fake.
        let audit = MemoryAuditSink::default();
        let err = run_install_checks(&env, &audit).unwrap_err();
        assert_eq!(err.0.check.name(), "libkrunfw");
    }

    // The no-KVM exit-gate scenario through this full entry point lives
    // under `tests/unit/install/` (file-structure.md: contract-with-the-
    // rest-of-the-system tests, not pure internal logic, belong there).

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
        assert!(audit.events.lock().unwrap().is_empty());
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
        // podman missing, but that must not hide the krun-runtime/
        // crun-version/passt/libkrunfw/betterleaks results -- unlike the
        // gate, the report doesn't stop at the first failure.
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
