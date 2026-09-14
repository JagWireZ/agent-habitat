//! Phase 1 exit-gate tests for `habitat-install` (`tmp/wip/implementation-plan.md`).
//!
//! These are black-box tests of the crate's public contract with the rest
//! of the system -- run through `run_install_checks`/`run_preflight`
//! exactly as `habitat-cli` calls them -- not pure internal logic, so per
//! `file-structure.md` Section 2 they live here under `tests/unit/install/`
//! rather than as inline `#[cfg(test)]` modules in `crates/install/src/`.
//! Wired into `cargo test` via the `[[test]]` target in
//! `crates/install/Cargo.toml`.

use habitat_audit::MemoryAuditSink;
use habitat_install::testing::FakeEnvironment;
use habitat_install::{run_install_checks, run_preflight};

/// Exit gate: "run preflight on a machine/nested-VM without KVM exposed
/// and confirm it actually reports absence, not a false positive
/// (recorded test, not inspection)."
///
/// Every other check is satisfied; only `/dev/kvm` is absent, simulating a
/// nested VM that hasn't had `/dev/kvm` passed through to it. Preflight
/// must fail closed, attribute the failure to the `kvm` check by name (not
/// a generic failure), and record exactly one distinctly-tagged
/// `preflight-failure` audit event -- never a silent pass.
#[test]
fn preflight_reports_missing_kvm_not_a_false_positive() {
    let env = FakeEnvironment::linux()
        .with_command_ok("podman --version", "podman version 5.0.0")
        .with_command_ok("podman info", "host: ...")
        .with_command_ok("crun-krun --version", "crun-krun 1.14");
    // Deliberately no `/dev/kvm` and no /proc/cpuinfo virt flag registered.

    let audit = MemoryAuditSink::default();
    let result = run_preflight(&env, &audit);

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

/// Exit gate: "an intentionally-broken containerd/Kata install fails
/// closed with a non-zero exit and a distinctly-tagged log entry" --
/// carried over to the current stack as: an intentionally-broken
/// Podman/krun install fails closed the same way.
///
/// `crun-krun` is present-but-broken (analogous to a misconfigured OCI
/// runtime that fails to report its version) -- everything upstream of it
/// (host OS, KVM, podman reachability) is otherwise healthy.
#[test]
fn broken_krun_runtime_install_fails_closed_with_distinct_tag() {
    let env = FakeEnvironment::linux()
        .with_existing_path("/dev/kvm")
        .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc")
        .with_command_ok("podman --version", "podman version 5.0.0")
        .with_command_ok("podman info", "host: ...")
        .with_command_failure("crun-krun --version", "error: no such runtime handler");

    let audit = MemoryAuditSink::default();
    let err = run_preflight(&env, &audit)
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

    // Also exercised via `habitat install` directly (host-os check first,
    // so use a fully Linux+podman-healthy env to reach the same
    // krun-runtime failure through that entry point too).
    let install_audit = MemoryAuditSink::default();
    let install_err = run_install_checks(&env, &install_audit)
        .expect_err("`habitat install` must also fail closed on a broken krun-runtime install");
    assert_eq!(install_err.0.check.name(), "krun-runtime");
    let install_events = install_audit.events.lock().unwrap();
    assert_eq!(install_events[0].kind.tag(), "install-failure");
}

/// Exit gate: "installer run twice on an already-correct host produces no
/// changes the second time."
///
/// `habitat install` is verify-only: nothing in `Environment` exposes a
/// mutating operation (`os_family`, `path_exists`, `can_open_read_write`,
/// `read_to_string`, `run_command` are all read-only probes), and
/// `run_install_checks` takes `&E`, never `&mut E` -- so by construction it
/// cannot leave the host in a different state than it found it. This test
/// confirms the *observable* side of that: run against an
/// already-correct host twice and get byte-identical outcomes (`Ok`, zero
/// audit events) both times.
#[test]
fn install_run_twice_on_already_correct_host_makes_no_changes() {
    let env = FakeEnvironment::linux()
        .with_command_ok("podman --version", "podman version 5.0.0")
        .with_command_ok("podman info", "host: ...")
        .with_command_ok("crun-krun --version", "crun-krun 1.14");

    let first_audit = MemoryAuditSink::default();
    let first = run_install_checks(&env, &first_audit);
    assert!(first.is_ok());
    assert!(first_audit.events.lock().unwrap().is_empty());

    let second_audit = MemoryAuditSink::default();
    let second = run_install_checks(&env, &second_audit);
    assert!(second.is_ok());
    assert!(
        second_audit.events.lock().unwrap().is_empty(),
        "second run must produce no audit events either -- no new state, no new log entries"
    );
}
