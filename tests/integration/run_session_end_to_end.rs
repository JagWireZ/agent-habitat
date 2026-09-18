//! Phase 7 exit gate: "an end-to-end run (`habitat run --config
//! sandbox.yaml -- <agent>`) across multiple prompts, at least one
//! host-side edit between prompts, and at least one agent tool call,
//! produces the expected sequence of audit events and applied patches in
//! the real working directory."
//!
//! Runs through `habitat_cli::run::run_full_session` -- the actual Phase 7
//! driver, not hand-driven subsystems the way Phase 6's own
//! `tests/integration/audit_end_to_end.rs` stood in for the (then
//! nonexistent) driver. VM launch/teardown and the guest exec channel are
//! faked (no real KVM/SSH in this dev container or CI, same constraint
//! every other phase's exit gate hits); the disk-build pipeline and the
//! host side of every sync round run for real (`git`, `mke2fs`,
//! `debugfs`, matching Phase 2's own precedent that those are ordinary
//! dev-container/CI tooling, unlike KVM/Podman/krun).
//!
//! **Why a custom, pattern-matching guest runner instead of the shared
//! `WsFakeCommandRunner`:** `sync::sync_host_to_sandbox`'s guest-apply
//! step copies the patch to a randomly-named temp file
//! (`patch::write_temp_patch_file`) both on the host and inside the
//! `scp`/`git apply` argv it builds for the guest, so the exact
//! invocation string is not known ahead of time and can't be pre-keyed
//! into a plain exact-match fake -- the same reason
//! `tests/integration/audit_end_to_end.rs` only ever exercises
//! `sync_sandbox_to_host`'s "Applied" path with the shared fake, never
//! `sync_host_to_sandbox`'s. This test needs *both* directions to
//! actually apply (to cover the exit gate's host-edit-between-prompts
//! and agent-tool-call requirements in one real run), so it uses a small
//! bespoke runner matching on command shape instead of an exact string.

use habitat_audit::MemoryAuditSink;
use habitat_cli::run::{self, AgentInvocation, SessionDeps, SessionPaths};
use habitat_install::testing::FakeEnvironment;
use habitat_policy::config::ProjectConfig;
use habitat_policy::secrets_scan::Toggle;
use habitat_vm::command_runner::testing::FakeCommandRunner as VmFakeCommandRunner;
use habitat_vm::launcher::build_run_args;
use habitat_vm::session::{LaunchRequest, SessionId};
use habitat_workspace::command_runner::{CommandRunner, SystemCommandRunner};
use habitat_workspace::sync::SyncOutcome;
use std::cell::{Cell, RefCell};
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitStatus, Output};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-run-e2e-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ok_output(stdout: &str) -> Output {
    Output {
        status: ExitStatus::from_raw(0),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    }
}

/// The fixed patch the guest reports on its one "dirty" round: a new file,
/// same shape as `tests/integration/audit_end_to_end.rs`'s own fixture
/// (proven to apply cleanly via real `git apply`).
const AGENT_PATCH: &str = "diff --git a/from-agent.txt b/from-agent.txt\n\
new file mode 100644\n\
index 0000000..1111111\n\
--- /dev/null\n\
+++ b/from-agent.txt\n\
@@ -0,0 +1 @@\n\
+hello from the agent\n";

/// Matches on command *shape* (program + substrings of the joined,
/// shell-quoted remote command) rather than an exact string, so
/// `sync_host_to_sandbox`'s randomly-named temp patch file doesn't need
/// to be predicted. Stateful only for `git status --porcelain`: empty on
/// every call except the last, so exactly one `sync_sandbox_to_host`
/// round (the final one) finds a real guest-side change to sync back --
/// avoiding a second, doomed re-application of the same fixed patch.
struct ScriptedGuestRunner {
    total_status_calls: u32,
    status_call_count: Cell<u32>,
    invocations: RefCell<Vec<String>>,
}

impl ScriptedGuestRunner {
    fn new(total_status_calls: u32) -> Self {
        ScriptedGuestRunner {
            total_status_calls,
            status_call_count: Cell::new(0),
            invocations: RefCell::new(Vec::new()),
        }
    }
}

impl CommandRunner for ScriptedGuestRunner {
    fn run_with_env(&self, _env: &[(&str, &str)], program: &str, args: &[&str]) -> io::Result<Output> {
        let joined = args.join(" ");
        self.invocations.borrow_mut().push(format!("{program} {joined}"));
        let last = args.last().copied().unwrap_or("");

        match program {
            "scp" => Ok(ok_output("")),
            "ssh" if last.contains("'status' '--porcelain'") => {
                let n = self.status_call_count.get() + 1;
                self.status_call_count.set(n);
                if n == self.total_status_calls {
                    Ok(ok_output(" M guest-dirty-marker\n"))
                } else {
                    Ok(ok_output(""))
                }
            }
            "ssh" if last.contains("'add' '-A'") => Ok(ok_output("")),
            "ssh" if last.contains("'commit' '--quiet'") => Ok(ok_output("")),
            "ssh" if last.contains("'diff' '") && last.contains("'HEAD'") => {
                Ok(ok_output(AGENT_PATCH))
            }
            "ssh" if last.contains("'apply' '--check'") => Ok(ok_output("")),
            "ssh" if last.contains("'apply' '") => Ok(ok_output("")),
            "ssh" if last.contains("'fake-agent'") => Ok(ok_output("agent turn completed\n")),
            _ => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("ScriptedGuestRunner: unrecognized invocation: {program} {joined}"),
            )),
        }
    }
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

fn write_fake_ssh_keypair(key_path: &std::path::Path) {
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    std::fs::write(key_path, "-----BEGIN FAKE PRIVATE KEY-----\n").unwrap();
    let mut pub_path = key_path.as_os_str().to_owned();
    pub_path.push(".pub");
    std::fs::write(pub_path, "ssh-ed25519 AAAAtestFakeKey habitat-session\n").unwrap();
}

#[test]
fn multi_prompt_session_syncs_a_host_edit_and_an_agent_change_through_the_real_driver() {
    let env = passing_install_env();
    let project_root = temp_dir("project");
    let state_dir = temp_dir("state");
    let paths = SessionPaths::new(&state_dir);

    let mut config = ProjectConfig::default();
    config.secrets_scan.content = Toggle::Disabled;

    write_fake_ssh_keypair(&paths.guest_ssh_key_path());

    let session_id = SessionId::from_name("habitat-run-e2e-session").unwrap();
    let launch_req = LaunchRequest {
        session_id: session_id.clone(),
        workspace_disk_path: paths.image_path(),
        guest_image: "localhost/habitat-guest:alpine".to_string(),
        resource_limits: config.resource_limits.clone(),
        egress_proxy_addr: "127.0.0.1:8443".parse().unwrap(),
        guest_ssh_public_key: "ssh-ed25519 AAAAtestFakeKey habitat-session".to_string(),
        guest_ssh_private_key_path: paths.guest_ssh_key_path(),
    };
    let run_args_argv = build_run_args(&launch_req);
    let run_invocation = format!(
        "podman {}",
        run_args_argv.iter().map(String::as_str).collect::<Vec<_>>().join(" ")
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
        .with_ok(&format!("podman port {session_id} 2222/tcp"), "127.0.0.1:34567\n")
        .with_ok(&format!("podman rm --force --ignore {session_id}"), "");

    let host_runner = SystemCommandRunner;
    // Two prompts -> two `git status --porcelain` calls total; only the
    // last (second) one reports a guest-side change.
    let guest_runner = ScriptedGuestRunner::new(2);
    let audit = MemoryAuditSink::default();

    let deps = SessionDeps {
        install_env: &env,
        vm_runner: &vm_runner,
        host_runner: &host_runner,
        guest_runner: &guest_runner,
        audit: &audit,
    };

    let project_root_for_edit = project_root.clone();
    let mut prompt_n = 0;
    let prompts = std::iter::from_fn(move || {
        prompt_n += 1;
        match prompt_n {
            1 => Some("what does this project do?".to_string()),
            2 => {
                // The host-side edit between prompts (exit gate requirement):
                // the operator changes a real file while the agent is
                // "thinking" between turns, and it must reach the guest
                // before this second prompt does.
                std::fs::write(
                    project_root_for_edit.join("notes.txt"),
                    "a note the operator added between prompts\n",
                )
                .unwrap();
                Some("add a test for the new behavior".to_string())
            }
            _ => None,
        }
    });

    let summary = run::run_full_session(
        &deps,
        session_id,
        &project_root,
        &paths,
        &config,
        "localhost/habitat-guest:alpine",
        "127.0.0.1:8443".parse().unwrap(),
        &AgentInvocation {
            program: "fake-agent".to_string(),
            args: vec![],
        },
        prompts,
        |_| {},
    )
    .expect("the full session must succeed end to end");

    // Two full prompt rounds ran.
    assert_eq!(summary.rounds.len(), 2);

    // Round 1: nothing to sync host->sandbox yet (project started empty).
    assert!(matches!(summary.rounds[0].host_to_sandbox, SyncOutcome::NoOp));
    // Round 2: the host-side edit made between prompts is a real,
    // validated, applied patch into the guest.
    match &summary.rounds[1].host_to_sandbox {
        SyncOutcome::Applied { touched_paths, .. } => {
            assert!(
                touched_paths.iter().any(|p| p.contains("notes.txt")),
                "the host-side edit must be the thing that got synced in: {touched_paths:?}"
            );
        }
        other => panic!("expected the host-side edit to sync in as Applied, got {other:?}"),
    }

    // At least one agent tool call actually reached the guest, once per
    // prompt.
    let agent_calls = guest_runner
        .invocations
        .borrow()
        .iter()
        .filter(|inv| inv.contains("'fake-agent'"))
        .count();
    assert_eq!(agent_calls, 2, "the agent must run once per prompt");

    // The final round's guest-side change is synced back and actually
    // applied to the real project directory, not just reported.
    match &summary.rounds[1].sandbox_to_host {
        SyncOutcome::Applied { touched_paths, .. } => {
            assert!(touched_paths.iter().any(|p| p.contains("from-agent.txt")));
        }
        other => panic!("expected the agent's own change to sync back as Applied, got {other:?}"),
    }
    assert!(
        project_root.join("from-agent.txt").exists(),
        "the agent's change must be a real file in the real working directory, not just an in-memory patch"
    );
    assert_eq!(
        std::fs::read_to_string(project_root.join("from-agent.txt")).unwrap(),
        "hello from the agent\n"
    );

    // The full audit sequence: preflight, session start, one clean sync
    // (the host edit going in), one clean sync (the agent's change
    // coming back), session stop. No flags anywhere in a fully clean run.
    let tags: Vec<&str> = audit.events.lock().unwrap().iter().map(|e| e.kind.tag()).collect();
    assert_eq!(
        tags,
        vec![
            "preflight-pass",
            "session-start",
            "sync-applied",
            "sync-applied",
            "session-stop",
        ],
        "unexpected audit sequence: {tags:?}"
    );

    assert!(
        !paths.image_path().exists(),
        "teardown must have deleted the disposable disk image"
    );

    std::fs::remove_dir_all(&project_root).unwrap();
    std::fs::remove_dir_all(&state_dir).unwrap();
}
