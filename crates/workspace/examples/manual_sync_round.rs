//! Manual driver for `tests/manual/validate-sync.sh` Steps 4-5.
//!
//! Phase 4 has no CLI wiring yet (`habitat run`'s prompt loop is Phase
//! 7's job), so there is nothing to invoke
//! `habitat_workspace::sync::sync_host_to_sandbox`/`sync_sandbox_to_host`
//! against a real, booted guest except a small standalone driver. This
//! exists only for that manual runbook -- the sync logic itself is
//! already covered for real by `tests/unit/workspace/sync_exit_gate.rs`
//! and `tests/adversarial/sync_patch_validation.rs` against
//! `FakeCommandRunner`; this example's only job is to make one real,
//! discrete `sync_*` call against a real guest so the runbook's
//! process-inventory check has something real to observe around.
//!
//! Usage:
//!   cargo run -p habitat-workspace --example manual_sync_round -- \
//!     <host-to-sandbox|sandbox-to-host> <ssh-host> <ssh-port> <ssh-key-path> <state-dir>
//!
//! Run `host-to-sandbox` first (Step 4): seeds/updates a file under
//! `<state-dir>/project` and syncs it into the guest's `/workspace`.
//! Then run `sandbox-to-host` (Step 5) with the same `<state-dir>`: the
//! guest's `/workspace` now has that untracked file sitting in it, so
//! `sync_sandbox_to_host` has something real to detect and pull back.

use habitat_audit::MemoryAuditSink;
use habitat_policy::blocklist;
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::guest_exec::GuestEndpoint;
use habitat_workspace::sync::{
    self, FlaggedPatchStore, HostToSandboxRequest, SandboxToHostRequest,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [direction, host, port, key_path, state_dir] = match <[String; 5]>::try_from(args) {
        Ok(a) => a,
        Err(_) => {
            eprintln!(
                "usage: manual_sync_round <host-to-sandbox|sandbox-to-host> <ssh-host> <ssh-port> <ssh-key-path> <state-dir>"
            );
            return ExitCode::FAILURE;
        }
    };
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("manual_sync_round: '{port}' is not a valid port number");
            return ExitCode::FAILURE;
        }
    };

    let state_dir = PathBuf::from(state_dir);
    let project_root = state_dir.join("project");
    let mirror_dir = state_dir.join("mirror");
    let flagged_dir = state_dir.join("flagged");

    let guest = GuestEndpoint {
        host: &host,
        port,
        private_key_path: Path::new(&key_path),
    };
    let patterns = blocklist::default_patterns();
    let store = FlaggedPatchStore::new(&flagged_dir);
    let runner = SystemCommandRunner;
    let audit = MemoryAuditSink::default();

    let result = match direction.as_str() {
        "host-to-sandbox" => {
            if let Err(e) = std::fs::create_dir_all(&project_root) {
                eprintln!("manual_sync_round: could not create project_root: {e}");
                return ExitCode::FAILURE;
            }
            if !mirror_dir.join(".git").exists() {
                if let Err(e) = std::fs::create_dir_all(&mirror_dir) {
                    eprintln!("manual_sync_round: could not create mirror_dir: {e}");
                    return ExitCode::FAILURE;
                }
                let init = std::process::Command::new("git")
                    .args(["-C", mirror_dir.to_str().unwrap(), "init", "--quiet"])
                    .output();
                if let Err(e) = init {
                    eprintln!("manual_sync_round: could not git init mirror_dir: {e}");
                    return ExitCode::FAILURE;
                }
            }
            // A real host-side edit every run, so this is never a no-op
            // even when re-run against an already-synced state dir.
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            if let Err(e) = std::fs::write(
                project_root.join("hello.txt"),
                format!("hello from the host, sync round {stamp}\n"),
            ) {
                eprintln!("manual_sync_round: could not write host-side file: {e}");
                return ExitCode::FAILURE;
            }

            let request = HostToSandboxRequest {
                project_root: &project_root,
                mirror_dir: &mirror_dir,
                guest,
                patterns: &patterns,
                flagged_store: &store,
            };
            sync::sync_host_to_sandbox(&request, &runner, &runner, &audit)
        }
        "sandbox-to-host" => {
            let request = SandboxToHostRequest {
                project_root: &project_root,
                mirror_dir: &mirror_dir,
                guest,
                patterns: &patterns,
                flagged_store: &store,
            };
            sync::sync_sandbox_to_host(&request, &runner, &runner, &audit)
        }
        other => {
            eprintln!(
                "manual_sync_round: unknown direction '{other}' (expected 'host-to-sandbox' or 'sandbox-to-host')"
            );
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(outcome) => {
            println!("{direction}: {outcome:?}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{direction}: error: {e}");
            ExitCode::FAILURE
        }
    }
}
