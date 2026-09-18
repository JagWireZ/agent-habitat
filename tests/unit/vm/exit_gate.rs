//! Black-box exit-gate tests for `habitat-vm`, run through
//! `launcher::launch`/`launcher::teardown` as `habitat run` would call
//! them. A concrete escape attempt from inside an actually-booted guest
//! needs real KVM; see `tests/manual/validate-vm-launch.sh` instead.

use habitat_audit::MemoryAuditSink;
use habitat_policy::resource_limits::ResourceLimitsConfig;
use habitat_vm::command_runner::testing::FakeCommandRunner;
use habitat_vm::launcher::{self, build_run_args};
use habitat_vm::session::{LaunchRequest, LaunchedSession, SessionId};
use std::path::PathBuf;

fn request_with_limits(cpus: f64, memory_mb: u64) -> LaunchRequest {
    LaunchRequest {
        session_id: SessionId::from_name("habitat-exit-gate-session").unwrap(),
        workspace_disk_path: PathBuf::from("/tmp/habitat-exit-gate-session.img"),
        guest_image: "localhost/habitat-guest:alpine".to_string(),
        resource_limits: ResourceLimitsConfig { cpus, memory_mb },
        egress_proxy_addr: "127.0.0.1:8443".parse().unwrap(),
        guest_ssh_public_key: "ssh-ed25519 AAAAtest habitat-session".to_string(),
        guest_ssh_private_key_path: PathBuf::from("/tmp/habitat-exit-gate-session-key"),
    }
}

/// Resource limits from config show up on the real `podman run`
/// invocation, not just in an in-memory struct nothing acts on.
#[test]
fn resource_limits_from_config_reach_the_launch_command() {
    let request = request_with_limits(3.0, 6144);
    let args = build_run_args(&request);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let invocation = format!("podman {}", arg_refs.join(" "));
    let runner = FakeCommandRunner::default()
        .with_ok(&invocation, "containerid123\n")
        .with_ok(
            "podman port habitat-exit-gate-session 2222/tcp",
            "127.0.0.1:34567\n",
        );

    let audit = MemoryAuditSink::default();
    let launched = launcher::launch(&request, &runner, &audit).expect("launch must succeed");
    assert_eq!(launched.session_id, request.session_id);

    let cpus_idx = args.iter().position(|a| a == "--cpus").unwrap();
    assert_eq!(args[cpus_idx + 1], "3");
    let mem_idx = args.iter().position(|a| a == "--memory").unwrap();
    assert_eq!(args[mem_idx + 1], "6144m");
}

/// Teardown must destroy the virtual disk and VM state with no residual
/// artifact reachable from a later session. Disk deletion runs for real;
/// `podman rm` is mocked (container removal is KVM-dependent).
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
        guest_ssh_host: "127.0.0.1".to_string(),
        guest_ssh_port: 34567,
        guest_ssh_private_key_path: PathBuf::from("/tmp/habitat-exit-gate-teardown-key"),
    };
    let runner = FakeCommandRunner::default().with_ok(
        "podman rm --force --ignore habitat-exit-gate-teardown",
        "habitat-exit-gate-teardown\n",
    );

    let audit = MemoryAuditSink::default();
    launcher::teardown(&session, &runner, &audit).expect("teardown must succeed");

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

/// Tearing down an already-torn-down session must succeed, not fail.
#[test]
fn teardown_run_twice_makes_no_further_changes() {
    let session = LaunchedSession {
        session_id: SessionId::from_name("habitat-exit-gate-idempotent").unwrap(),
        workspace_disk_path: PathBuf::from("/tmp/habitat-exit-gate-idempotent-gone.img"),
        guest_ssh_host: "127.0.0.1".to_string(),
        guest_ssh_port: 34567,
        guest_ssh_private_key_path: PathBuf::from("/tmp/habitat-exit-gate-idempotent-gone-key"),
    };
    let runner = FakeCommandRunner::default().with_ok(
        "podman rm --force --ignore habitat-exit-gate-idempotent",
        "",
    );

    let audit = MemoryAuditSink::default();
    assert!(launcher::teardown(&session, &runner, &audit).is_ok());
    assert!(
        launcher::teardown(&session, &runner, &audit).is_ok(),
        "second teardown of an already-gone session must not error"
    );
}
