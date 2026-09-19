//! Phase 6 exit-gate smoke test: drives install/vm/egress/workspace
//! against one shared audit sink and confirms every boundary-crossing
//! event kind the exit gate calls out -- "session start, an allow, a
//! deny, a clean sync, a flagged/corrupted sync, a teardown" -- actually
//! appears in the unified log. `habitat run`'s own lifecycle driver
//! doesn't exist yet (Phase 7), so this test calls each subsystem's
//! entry point directly, the same way `crates/workspace/examples/
//! manual_sync_round.rs` stood in for the missing prompt loop in Phase 4.
//!
//! Also covers the exit gate's injection-safety half: a crafted, entirely
//! attacker-controlled SNI hostname (containing shell metacharacters)
//! flows through `EgressDenied` and comes out JSON-escaped, never in a
//! form that could execute anywhere the log is displayed or parsed.
//!
//! Sync now runs entirely locally against the shared workspace directory
//! (no guest, no SSH -- see `crates/workspace/src/sync.rs`'s module doc),
//! through a single runner. The "flagged/corrupted sync" step below fakes
//! `status`/`add`/`commit`/`diff` but lets any `git apply` invocation run
//! for real via [`HybridRunner`], since `structurally_valid`'s temp patch
//! file path is only known at call time.

use habitat_audit::{EventKind, MemoryAuditSink};
use habitat_egress::dialer::testing::FakeDialer;
use habitat_egress::proxy::{handle_connection, ConnectionOutcome};
use habitat_egress::sni::testing::build_client_hello;
use habitat_install::testing::FakeEnvironment;
use habitat_install::run_preflight;
use habitat_policy::resource_limits::ResourceLimitsConfig;
use habitat_vm::command_runner::testing::FakeCommandRunner as VmFakeCommandRunner;
use habitat_vm::launcher::{self, build_run_args};
use habitat_vm::session::{LaunchRequest, LaunchedSession, SessionId};
use habitat_workspace::command_runner::testing::FakeCommandRunner as WsFakeCommandRunner;
use habitat_workspace::command_runner::{CommandRunner, SystemCommandRunner};
use habitat_workspace::sync::{self, FlaggedPatchStore, SandboxToHostRequest, SyncOutcome};
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Output;
use std::thread;

/// See `tests/unit/workspace/sync_exit_gate.rs`'s own `HybridRunner` --
/// same reasoning, duplicated here rather than shared since neither crate
/// exposes test-only helpers to the other.
struct HybridRunner {
    fake: WsFakeCommandRunner,
}

impl CommandRunner for HybridRunner {
    fn run_with_env(
        &self,
        env: &[(&str, &str)],
        program: &str,
        args: &[&str],
    ) -> io::Result<Output> {
        if program == "git" && args.contains(&"apply") {
            SystemCommandRunner.run_with_env(env, program, args)
        } else {
            self.fake.run_with_env(env, program, args)
        }
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-audit-e2e-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn status_key(workspace_str: &str) -> String {
    format!("git -C {workspace_str} status --porcelain")
}

fn add_key(workspace_str: &str) -> String {
    format!("git -C {workspace_str} add -A")
}

fn commit_key(workspace_str: &str) -> String {
    format!("git -C {workspace_str} commit --quiet --allow-empty -m habitat sync")
}

fn diff_key(workspace_str: &str) -> String {
    format!("git -C {workspace_str} diff HEAD~1 HEAD")
}

fn launch_request() -> LaunchRequest {
    LaunchRequest {
        session_id: SessionId::from_name("habitat-audit-e2e-session").unwrap(),
        workspace_host_dir: PathBuf::from("/tmp/habitat-audit-e2e-session-workspace"),
        guest_image: "localhost/habitat-guest:alpine".to_string(),
        resource_limits: ResourceLimitsConfig {
            cpus: 2.0,
            memory_mb: 2048,
        },
        egress_proxy_addr: "127.0.0.1:8443".parse().unwrap(),
        guest_ssh_public_key: "ssh-ed25519 AAAAtest habitat-audit-e2e".to_string(),
        guest_ssh_private_key_path: PathBuf::from("/tmp/habitat-audit-e2e-session-key"),
    }
}

fn connect_guest_and_send(proxy_addr: std::net::SocketAddr, bytes: &[u8]) -> TcpStream {
    let mut guest = TcpStream::connect(proxy_addr).unwrap();
    guest.write_all(bytes).unwrap();
    guest.shutdown(Shutdown::Write).unwrap();
    guest
}

/// The exit gate's own smoke-test list, in order: session start, an
/// allow, a deny, a clean sync, a flagged/corrupted sync, a teardown --
/// every one of `EventKind`'s lifecycle/egress/sync variants shows up in
/// one shared log. There is no separate `VmLaunch`/`VmTeardown` pair
/// (see `EventKind::SessionStop`'s doc comment) -- `SessionStart`/
/// `SessionStop` *are* this test's "session start"/"teardown" steps.
#[test]
fn every_boundary_event_kind_appears_in_the_unified_log() {
    let audit = MemoryAuditSink::default();

    // 1. Session start (VM launch attempt).
    let request = launch_request();
    let args = build_run_args(&request);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let invocation = format!("podman {}", arg_refs.join(" "));
    let vm_runner = VmFakeCommandRunner::default()
        .with_ok(&invocation, "containerid123\n")
        .with_ok(
            "podman port habitat-audit-e2e-session 2222/tcp",
            "127.0.0.1:34567\n",
        );
    let launched = launcher::launch(&request, &vm_runner, &audit).expect("launch must succeed");

    // 2. An allowed egress connection.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream_handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).unwrap_or(0);
        let _ = conn.write_all(b"pretend-upstream-response");
        let _ = conn.shutdown(Shutdown::Write);
    });
    let dialer = FakeDialer::default().with_route("api.anthropic.com", upstream_addr);
    let allowlist = vec!["api.anthropic.com".to_string()];
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let allow_hello = build_client_hello("api.anthropic.com");
    let guest_allow_handle = {
        let hello = allow_hello.clone();
        thread::spawn(move || {
            let mut guest = connect_guest_and_send(proxy_addr, &hello);
            let mut resp = Vec::new();
            let _ = guest.read_to_end(&mut resp);
        })
    };
    let (client, _) = proxy_listener.accept().unwrap();
    let outcome = handle_connection(client, &allowlist, &dialer, &audit).unwrap();
    assert!(matches!(outcome, ConnectionOutcome::Allowed { .. }));
    guest_allow_handle.join().unwrap();
    upstream_handle.join().unwrap();

    // 3. A denied egress connection.
    let deny_dialer = FakeDialer::default(); // no routes configured
    let deny_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let deny_addr = deny_listener.local_addr().unwrap();
    let deny_hello = build_client_hello("attacker.example");
    let guest_deny_handle = {
        let hello = deny_hello.clone();
        thread::spawn(move || {
            let mut guest = connect_guest_and_send(deny_addr, &hello);
            let mut resp = Vec::new();
            let _ = guest.read_to_end(&mut resp);
        })
    };
    let (client, _) = deny_listener.accept().unwrap();
    let outcome = handle_connection(client, &allowlist, &deny_dialer, &audit).unwrap();
    assert!(matches!(outcome, ConnectionOutcome::Denied { .. }));
    guest_deny_handle.join().unwrap();

    // 4. A clean sync (sandbox -> host apply). `status`/`add`/`commit`/
    // `diff` are faked; the real apply runs via `HybridRunner`.
    let project = temp_dir("project");
    let workspace = temp_dir("workspace");
    let flagged_dir = temp_dir("flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);
    let new_file_patch = "diff --git a/from-guest.txt b/from-guest.txt\n\
new file mode 100644\n\
index 0000000..1111111\n\
--- /dev/null\n\
+++ b/from-guest.txt\n\
@@ -0,0 +1 @@\n\
+hello from the guest\n";
    let workspace_str = workspace.to_str().unwrap();
    let clean_runner = HybridRunner {
        fake: WsFakeCommandRunner::default()
            .with_ok(&status_key(workspace_str), "?? from-guest.txt\n")
            .with_ok(&add_key(workspace_str), "")
            .with_ok(&commit_key(workspace_str), "")
            .with_ok(&diff_key(workspace_str), new_file_patch),
    };
    let clean_request = SandboxToHostRequest {
        project_root: &project,
        workspace_dir: &workspace,
        patterns: &[],
        flagged_store: &store,
    };
    let outcome = sync::sync_sandbox_to_host(&clean_request, &clean_runner, &audit).unwrap();
    assert!(matches!(outcome, SyncOutcome::Applied { .. }));

    // 5. A flagged/corrupted sync -- `diff` hands back garbage, so the
    // real `git apply --check` (via `HybridRunner`) genuinely rejects it.
    let corrupt_project = temp_dir("corrupt-project");
    std::fs::write(corrupt_project.join("real.txt"), "original\n").unwrap();
    let corrupt_workspace = temp_dir("corrupt-workspace");
    let corrupt_flagged_dir = temp_dir("corrupt-flagged");
    let corrupt_store = FlaggedPatchStore::new(&corrupt_flagged_dir);
    let corrupt_workspace_str = corrupt_workspace.to_str().unwrap();
    let corrupt_runner = HybridRunner {
        fake: WsFakeCommandRunner::default()
            .with_ok(&status_key(corrupt_workspace_str), " M real.txt\n")
            .with_ok(&add_key(corrupt_workspace_str), "")
            .with_ok(&commit_key(corrupt_workspace_str), "")
            .with_ok(
                &diff_key(corrupt_workspace_str),
                "this is not a real unified diff -- just noise\n",
            ),
    };
    let corrupt_request = SandboxToHostRequest {
        project_root: &corrupt_project,
        workspace_dir: &corrupt_workspace,
        patterns: &[],
        flagged_store: &corrupt_store,
    };
    let outcome = sync::sync_sandbox_to_host(&corrupt_request, &corrupt_runner, &audit).unwrap();
    assert!(matches!(outcome, SyncOutcome::Flagged { .. }));

    // 6. Teardown.
    let session = LaunchedSession {
        session_id: launched.session_id.clone(),
        workspace_host_dir: launched.workspace_host_dir.clone(),
        guest_ssh_host: launched.guest_ssh_host.clone(),
        guest_ssh_port: launched.guest_ssh_port,
        guest_ssh_private_key_path: launched.guest_ssh_private_key_path.clone(),
    };
    let teardown_runner = VmFakeCommandRunner::default().with_ok(
        "podman rm --force --ignore habitat-audit-e2e-session",
        "habitat-audit-e2e-session\n",
    );
    launcher::teardown(&session, &teardown_runner, &audit).expect("teardown must succeed");

    // Every event kind the exit gate's smoke test names actually appears,
    // in the order the six steps above ran.
    let events = audit.events.lock().unwrap();
    let tags: Vec<&str> = events.iter().map(|e| e.kind.tag()).collect();
    assert_eq!(
        tags,
        vec![
            "session-start",
            "egress-allowed",
            "egress-denied",
            "sync-applied",
            "sync-flagged",
            "session-stop",
        ],
        "unified log must show every boundary event kind, in order: {tags:?}"
    );

    std::fs::remove_dir_all(&project).unwrap();
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::remove_dir_all(&flagged_dir).unwrap();
    std::fs::remove_dir_all(&corrupt_project).unwrap();
    let _ = std::fs::remove_dir_all(&corrupt_workspace);
    std::fs::remove_dir_all(&corrupt_flagged_dir).unwrap();
}

/// The preflight/install "pass" events (added this phase) land in the
/// same unified sink as everything else -- a clean run is visible, not
/// silent.
#[test]
fn preflight_and_install_pass_events_land_in_the_unified_log() {
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
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::PreflightPass);
}

/// Exit-gate injection-safety check: an entirely attacker-controlled SNI
/// hostname (arbitrary bytes on the wire, per `crate::sni`'s doc comment)
/// carrying shell metacharacters must come out of the audit line
/// JSON-escaped, never in a form that could be interpreted if the line
/// were ever displayed or parsed -- and it's real end-to-end, not a
/// synthetic payload handed straight to `AuditEvent::now`.
#[test]
fn a_malicious_sni_hostname_is_escaped_not_executable_in_the_audit_line() {
    let audit = MemoryAuditSink::default();
    let dialer = FakeDialer::default(); // no routes -- denied regardless
    let allowlist = vec!["api.anthropic.com".to_string()];

    let malicious_host = "$(rm -rf /); `id`; \"; DROP TABLE sessions; --";
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let hello = build_client_hello(malicious_host);
    let guest_handle = thread::spawn(move || {
        let mut guest = connect_guest_and_send(proxy_addr, &hello);
        let mut resp = Vec::new();
        let _ = guest.read_to_end(&mut resp);
    });
    let (client, _) = proxy_listener.accept().unwrap();
    let outcome = handle_connection(client, &allowlist, &dialer, &audit).unwrap();
    assert_eq!(
        outcome,
        ConnectionOutcome::Denied {
            host: Some(malicious_host.to_string())
        }
    );
    guest_handle.join().unwrap();

    let events = audit.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::EgressDenied);
    assert_eq!(events[0].check.as_deref(), Some(malicious_host));

    let line = events[0].to_json_line();
    assert!(line.starts_with('{') && line.ends_with('}'));
    assert!(!line.contains('\n') && !line.contains('\r'));
    // The raw payload's unescaped double quote must not appear -- only
    // its escaped form -- so the line stays one well-formed JSON object
    // rather than a value that spills out of its own string field.
    assert!(!line.contains("; \""));
    assert!(line.contains("\\\""));
}
