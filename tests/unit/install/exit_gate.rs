//! Black-box exit-gate tests for `habitat-install`, run through
//! `run_install_checks`/`run_preflight` as `habitat-cli` calls them.

use habitat_audit::MemoryAuditSink;
use habitat_install::testing::FakeEnvironment;
use habitat_install::{run_install_checks, run_preflight};

/// Every other check is satisfied; only `/dev/kvm` is absent, simulating a
/// nested VM without KVM passthrough. Preflight must fail closed,
/// attribute the failure to the `kvm` check by name, and record exactly
/// one `preflight-failure` audit event.
#[test]
fn preflight_reports_missing_kvm_not_a_false_positive() {
    let env = FakeEnvironment::linux()
        .with_command_ok("podman --version", "podman version 5.0.0")
        .with_command_ok("podman info", "host: ...")
        .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n");
    // Deliberately no `/dev/kvm` and no /proc/cpuinfo virt flag registered.

    let audit = MemoryAuditSink::default();
    let result = run_preflight(&env, &audit, false);

    let err = result.expect_err("preflight must fail closed when /dev/kvm is absent, not pass");
    assert_eq!(
        err.0.check.name(),
        "kvm",
        "failure must be attributed to the kvm check specifically, not a generic failure"
    );

    let events = audit.events.lock().unwrap();
    assert_eq!(
        events.len(),
        1,
        "exactly one audit event, not zero and not several"
    );
    assert_eq!(events[0].kind.tag(), "preflight-failure");
    assert_eq!(events[0].check.as_deref(), Some("kvm"));
}

/// An intentionally-broken Podman/krun install must fail closed with a
/// distinctly-tagged log entry -- `crun-krun` is present but broken while
/// everything upstream (host OS, KVM, podman reachability) is healthy.
#[test]
fn broken_krun_runtime_install_fails_closed_with_distinct_tag() {
    let env = FakeEnvironment::linux()
        .with_existing_path("/dev/kvm")
        .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc")
        .with_command_ok("podman --version", "podman version 5.0.0")
        .with_command_ok("podman info", "host: ...")
        .with_command_failure("krun --version", "error: no such runtime handler");

    let audit = MemoryAuditSink::default();
    let err = run_preflight(&env, &audit, false)
        .expect_err("a broken krun-runtime install must fail closed, not be treated as available");
    assert_eq!(err.0.check.name(), "krun-runtime");

    let events = audit.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].kind.tag(),
        "preflight-failure",
        "distinctly tagged -- not lumped in with an ordinary event"
    );
    assert_eq!(events[0].check.as_deref(), Some("krun-runtime"));

    // Also exercised via `habitat install` directly.
    let install_audit = MemoryAuditSink::default();
    let install_err = run_install_checks(&env, &install_audit)
        .expect_err("`habitat install` must also fail closed on a broken krun-runtime install");
    assert_eq!(install_err.0.check.name(), "krun-runtime");
    let install_events = install_audit.events.lock().unwrap();
    assert_eq!(install_events[0].kind.tag(), "install-failure");
}

/// Content-based secrets scanning must never silently degrade to no
/// scanning just because the operator hasn't installed the scanner.
/// Everything else on this host is healthy; `betterleaks` alone is absent.
#[test]
fn preflight_fails_closed_when_betterleaks_enabled_but_binary_missing() {
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
    let err = run_preflight(&env, &audit, true).expect_err(
        "secrets_scan.content enabled with betterleaks missing must fail closed, not silently skip scanning",
    );
    assert_eq!(err.0.check.name(), "betterleaks");

    let events = audit.events.lock().unwrap();
    assert_eq!(events.len(), 1, "exactly one distinctly-tagged failure");
    assert_eq!(events[0].kind.tag(), "preflight-failure");
    assert_eq!(events[0].check.as_deref(), Some("betterleaks"));

    // The same host with content scanning left at its project's declared
    // default of disabled must not be blocked on a binary it doesn't need.
    let audit_disabled = MemoryAuditSink::default();
    assert!(
        run_preflight(&env, &audit_disabled, false).is_ok(),
        "disabled content scanning must not require betterleaks"
    );
    let events = audit_disabled.events.lock().unwrap();
    assert_eq!(events.len(), 1, "a clean run logs its pass, not silence");
    assert_eq!(events[0].kind.tag(), "preflight-pass");
}

/// `habitat install` is verify-only by construction (`Environment` exposes
/// only read-only probes, and `run_install_checks` takes `&E` never `&mut
/// E`) -- this confirms the observable side: two runs against an
/// already-correct host produce byte-identical outcomes.
#[test]
fn install_run_twice_on_already_correct_host_makes_no_changes() {
    let env = FakeEnvironment::linux()
        .with_command_ok("podman --version", "podman version 5.0.0")
        .with_command_ok("podman info", "host: ...")
        .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n")
        .with_command_ok("passt --version", "passt 0.0~git\n")
        .with_command_ok("ldconfig -p", "\tlibkrunfw.so.5 => /lib64/libkrunfw.so.5\n");

    let first_audit = MemoryAuditSink::default();
    let first = run_install_checks(&env, &first_audit);
    assert!(first.is_ok());
    let first_events = first_audit.events.lock().unwrap();
    assert_eq!(first_events.len(), 1);
    assert_eq!(first_events[0].kind.tag(), "install-pass");

    let second_audit = MemoryAuditSink::default();
    let second = run_install_checks(&env, &second_audit);
    assert!(second.is_ok());
    let second_events = second_audit.events.lock().unwrap();
    assert_eq!(
        second_events.len(),
        1,
        "second run must produce the same single pass event -- no new state, no new log shape"
    );
    assert_eq!(second_events[0].kind.tag(), "install-pass");
}
