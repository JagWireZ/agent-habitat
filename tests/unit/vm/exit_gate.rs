//! Phase 3 exit-gate tests for `habitat-vm` (`tmp/wip/implementation-plan.md`).
//!
//! These are black-box tests of the crate's public contract with the
//! rest of the system -- run through `launcher::launch`/`launcher::teardown`
//! exactly as a later phase's `habitat run` would call them -- not pure
//! internal logic, so per `file-structure.md` Section 2 they live here
//! under `tests/unit/vm/` rather than as inline `#[cfg(test)]` modules in
//! `crates/vm/src/`. Wired into `cargo test` via the `[[test]]` target in
//! `crates/vm/Cargo.toml`.
//!
//! The other half of Phase 3's exit gate -- a concrete escape attempt
//! from inside an actually-booted guest fails -- needs real KVM this dev
//! container and this project's CI don't have; see
//! `tests/manual/validate-vm-launch.sh` for that runbook instead.

use habitat_policy::resource_limits::ResourceLimitsConfig;
use habitat_vm::command_runner::testing::FakeCommandRunner;
use habitat_vm::launcher::{self, build_run_args};
use habitat_vm::session::{LaunchRequest, LaunchedSession, SessionId};
use std::path::PathBuf;

fn request_with_limits(cpus: f64, memory_mb: u64) -> LaunchRequest {
    LaunchRequest {
        session_id: SessionId::from_name("habitat-exit-gate-session").unwrap(),
        workspace_disk_path: PathBuf::from("/tmp/habitat-exit-gate-session.img"),
        guest_image: "localhost/habitat-guest:almalinux".to_string(),
        resource_limits: ResourceLimitsConfig { cpus, memory_mb },
    }
}

/// Exit gate: resource limits read from the shared config (Phase 7 will
/// wire the actual `--config` read; this confirms the value actually
/// reaches the launch command once it's in hand, not just that the type
/// exists) show up on the real `podman run` invocation, not just in an
/// in-memory struct nothing acts on.
#[test]
fn resource_limits_from_config_reach_the_launch_command() {
    let request = request_with_limits(3.0, 6144);
    let args = build_run_args(&request);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let invocation = format!("podman {}", arg_refs.join(" "));
    let runner = FakeCommandRunner::default().with_ok(&invocation, "containerid123\n");

    let launched = launcher::launch(&request, &runner).expect("launch must succeed");
    assert_eq!(launched.session_id, request.session_id);

    let cpus_idx = args.iter().position(|a| a == "--cpus").unwrap();
    assert_eq!(args[cpus_idx + 1], "3");
    let mem_idx = args.iter().position(|a| a == "--memory").unwrap();
    assert_eq!(args[mem_idx + 1], "6144m");
}

/// Exit gate: "teardown actually destroys the virtual disk and VM state
/// with no residual writable artifact reachable from a later session."
/// Runs against a real temp file (disk deletion is an ordinary
/// filesystem operation, not KVM-dependent) and a mocked `podman rm`
/// (container removal is).
#[test]
fn teardown_leaves_no_residual_disk_image_or_container() {
    let dir = std::env::temp_dir().join(format!(
        "habitat-vm-exit-gate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let image_path = dir.join("session.img");
    std::fs::write(&image_path, b"session disk contents").unwrap();

    let session = LaunchedSession {
        session_id: SessionId::from_name("habitat-exit-gate-teardown").unwrap(),
        workspace_disk_path: image_path.clone(),
    };
    let runner = FakeCommandRunner::default().with_ok(
        "podman rm --force --ignore habitat-exit-gate-teardown",
        "habitat-exit-gate-teardown\n",
    );

    launcher::teardown(&session, &runner).expect("teardown must succeed");

    assert!(
        !image_path.exists(),
        "disk image must not survive teardown -- a later session must not be able to read it"
    );
    let invocations = runner.invocations.borrow();
    assert!(
        invocations
            .iter()
            .any(|i| i.contains("rm") && i.contains("--force") && i.contains("--ignore")),
        "teardown must actually force-remove the container, not just delete the disk"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

/// Exit gate companion: tearing down an already-torn-down session (the
/// container already gone, the disk already deleted) must succeed rather
/// than fail -- same idempotency bar as Phase 1's
/// install-run-twice-makes-no-changes exit gate, applied here to
/// teardown.
#[test]
fn teardown_run_twice_makes_no_further_changes() {
    let session = LaunchedSession {
        session_id: SessionId::from_name("habitat-exit-gate-idempotent").unwrap(),
        workspace_disk_path: PathBuf::from("/tmp/habitat-exit-gate-idempotent-gone.img"),
    };
    let runner = FakeCommandRunner::default().with_ok(
        "podman rm --force --ignore habitat-exit-gate-idempotent",
        "",
    );

    assert!(launcher::teardown(&session, &runner).is_ok());
    assert!(
        launcher::teardown(&session, &runner).is_ok(),
        "second teardown of an already-gone session must not error"
    );
}
