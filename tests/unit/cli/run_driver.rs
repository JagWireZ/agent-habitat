//! Unit tests for `habitat_cli::run`'s session driver, mirroring
//! `crates/cli/` (`file-structure.md` Section 2). Covers `run_full_session`'s
//! own wiring -- fail-closed ordering (preflight gates everything else)
//! and a minimal real happy path (disk built for real, VM launch/teardown
//! faked, prompt loop exercised with an immediate `exit`). The fuller
//! multi-prompt/host-edit/agent-tool-call scenario is
//! `tests/integration/run_session_end_to_end.rs`'s job.

use habitat_audit::{EventKind, MemoryAuditSink};
use habitat_cli::run::{self, SessionDeps, SessionPaths};
use habitat_install::testing::FakeEnvironment;
use habitat_policy::config::ProjectConfig;
use habitat_policy::secrets_scan::Toggle;
use habitat_vm::command_runner::testing::FakeCommandRunner as VmFakeCommandRunner;
use habitat_vm::launcher::build_run_args;
use habitat_vm::session::{LaunchRequest, SessionId};
use habitat_workspace::command_runner::SystemCommandRunner as WsSystemCommandRunner;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-cli-run-driver-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn passing_install_env() -> FakeEnvironment {
    FakeEnvironment::linux()
        .with_existing_path("/dev/kvm")
        .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc")
        .with_command_ok("podman --version", "podman version 5.0.0")
        .with_command_ok("podman info", "host: ...")
        .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n")
        .with_command_ok("passt --version", "passt 0.0~git\n")
        .with_command_ok("ldconfig -p", "\tlibkrunfw.so.5 => /lib64/libkrunfw.so.5\n")
}

/// Content scanning off so preflight doesn't also need a `betterleaks`
/// check faked -- this test is about the driver's own wiring, not the
/// content-scan preflight gate (already covered elsewhere).
fn no_content_scan_config() -> ProjectConfig {
    let mut config = ProjectConfig::default();
    config.secrets_scan.content = Toggle::Disabled;
    config
}

#[test]
fn preflight_failure_stops_before_disk_build_or_launch() {
    let env = FakeEnvironment::linux(); // no /dev/kvm -- fails the KVM check
    let vm_runner = VmFakeCommandRunner::default();
    let ws_runner = WsSystemCommandRunner;
    let audit = MemoryAuditSink::default();
    let deps = SessionDeps {
        install_env: &env,
        vm_runner: &vm_runner,
        host_runner: &ws_runner,
        guest_runner: &ws_runner,
        audit: &audit,
    };

    let project_root = temp_dir("project");
    let state_dir = temp_dir("state");
    let paths = SessionPaths::new(&state_dir);
    let config = no_content_scan_config();

    let result = run::run_full_session(
        &deps,
        SessionId::from_name("habitat-driver-test-preflight-fail").unwrap(),
        &project_root,
        &paths,
        &config,
        "localhost/habitat-guest:alpine",
        "127.0.0.1:8443".parse().unwrap(),
        &run::AgentInvocation {
            program: "fake-agent".to_string(),
            args: vec![],
        },
        std::iter::empty(),
        |_| {},
    );

    assert!(result.is_err(), "a failed preflight must stop the session");
    assert!(
        vm_runner.invocations.borrow().is_empty(),
        "nothing should reach the VM runner once preflight has already failed"
    );
    assert!(!paths.image_path().exists(), "no disk image should be built");

    let events = audit.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::PreflightFailure);

    std::fs::remove_dir_all(&project_root).unwrap();
    std::fs::remove_dir_all(&state_dir).unwrap();
}

fn write_fake_ssh_keypair(key_path: &std::path::Path) {
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    std::fs::write(key_path, "-----BEGIN FAKE PRIVATE KEY-----\n").unwrap();
    let mut pub_path = key_path.as_os_str().to_owned();
    pub_path.push(".pub");
    std::fs::write(pub_path, "ssh-ed25519 AAAAtestFakeKey habitat-session\n").unwrap();
}

#[test]
fn happy_path_builds_a_real_disk_launches_and_tears_down_with_an_immediate_exit() {
    let env = passing_install_env();
    let project_root = temp_dir("project");
    std::fs::write(project_root.join("README.md"), "hello project\n").unwrap();
    let state_dir = temp_dir("state");
    let paths = SessionPaths::new(&state_dir);
    let config = no_content_scan_config();

    // `guest_ssh::generate` reads the `.pub` file back off disk after
    // `ssh-keygen` reports success -- pre-seed it since the fake runner
    // below doesn't actually run a real `ssh-keygen`.
    write_fake_ssh_keypair(&paths.guest_ssh_key_path());

    let session_id = SessionId::from_name("habitat-driver-test-happy-path").unwrap();
    let launch_req = LaunchRequest {
        session_id: session_id.clone(),
        workspace_disk_path: paths.image_path(),
        guest_image: "localhost/habitat-guest:alpine".to_string(),
        resource_limits: config.resource_limits.clone(),
        egress_proxy_addr: "127.0.0.1:8443".parse().unwrap(),
        guest_ssh_public_key: "ssh-ed25519 AAAAtestFakeKey habitat-session".to_string(),
        guest_ssh_private_key_path: paths.guest_ssh_key_path(),
    };
    let run_args = build_run_args(&launch_req);
    let run_invocation = format!(
        "podman {}",
        run_args.iter().map(String::as_str).collect::<Vec<_>>().join(" ")
    );
    let key_path_str = paths.guest_ssh_key_path();
    let keygen_args = [
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        key_path_str.to_str().unwrap(),
        "-C",
        "habitat-session",
        "-q",
    ];
    let keygen_invocation = format!("ssh-keygen {}", keygen_args.join(" "));

    let vm_runner = VmFakeCommandRunner::default()
        .with_ok(&keygen_invocation, "")
        .with_ok(&run_invocation, "containerid123\n")
        .with_ok(
            &format!("podman port {session_id} 2222/tcp"),
            "127.0.0.1:34567\n",
        )
        .with_ok(&format!("podman rm --force --ignore {session_id}"), "");

    let ws_runner = WsSystemCommandRunner;
    let audit = MemoryAuditSink::default();
    let deps = SessionDeps {
        install_env: &env,
        vm_runner: &vm_runner,
        host_runner: &ws_runner,
        guest_runner: &ws_runner,
        audit: &audit,
    };

    let summary = run::run_full_session(
        &deps,
        session_id,
        &project_root,
        &paths,
        &config,
        "localhost/habitat-guest:alpine",
        "127.0.0.1:8443".parse().unwrap(),
        &run::AgentInvocation {
            program: "fake-agent".to_string(),
            args: vec![],
        },
        vec!["exit".to_string()],
        |_| panic!("an immediate 'exit' prompt must never reach the agent"),
    )
    .expect("the full session must succeed end to end");

    assert!(
        summary.rounds.is_empty(),
        "'exit' ends the session before any round runs"
    );

    let tags: Vec<&str> = audit
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|e| e.kind.tag())
        .collect();
    assert_eq!(
        tags,
        vec!["preflight-pass", "session-start", "session-stop"],
        "the real driver's audit sequence for a no-op session: {tags:?}"
    );

    std::fs::remove_dir_all(&project_root).unwrap();
    std::fs::remove_dir_all(&state_dir).unwrap();
}
