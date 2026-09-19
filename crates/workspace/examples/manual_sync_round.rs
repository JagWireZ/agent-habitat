//! Manual driver for `tests/manual/validate-sync.sh` Steps 4-5.
//!
//! No CLI wiring exists yet for `sync_host_to_sandbox`/`sync_sandbox_to_host`
//! against a real booted guest, so this small standalone driver exists
//! only for that manual runbook -- the sync logic itself is already
//! covered for real by `tests/unit/workspace/sync_exit_gate.rs` and
//! `tests/adversarial/sync_patch_validation.rs` against `FakeCommandRunner`.
//!
//! Usage:
//!   cargo run -p habitat-workspace --example manual_sync_round -- \
//!     <host-to-sandbox|sandbox-to-host> <state-dir>
//!
//! `<state-dir>/workspace` must already be the disposable, git-seeded
//! staging directory bind-mounted into the guest at `/workspace` (see
//! `sync`'s own module doc -- there is no separate host-only mirror
//! anymore, and no guest endpoint to pass, since sync runs entirely
//! locally against that shared directory).
//!
//! Run `host-to-sandbox` first (Step 4): seeds/updates a file under
//! `<state-dir>/project` and syncs it into `<state-dir>/workspace`
//! (the guest's `/workspace`, via the bind mount). Then run
//! `sandbox-to-host` (Step 5) with the same `<state-dir>`: the guest
//! should have written something new directly into that same directory
//! by then, so `sync_sandbox_to_host` has something real to detect and
//! pull back into `<state-dir>/project`.

use habitat_audit::MemoryAuditSink;
use habitat_policy::blocklist;
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::sync::{self, FlaggedPatchStore, HostToSandboxRequest, SandboxToHostRequest};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [direction, state_dir] = match <[String; 2]>::try_from(args) {
        Ok(a) => a,
        Err(_) => {
            eprintln!(
                "usage: manual_sync_round <host-to-sandbox|sandbox-to-host> <state-dir>"
            );
            return ExitCode::FAILURE;
        }
    };

    let state_dir = PathBuf::from(state_dir);
    let project_root = state_dir.join("project");
    let workspace_dir = state_dir.join("workspace");
    let flagged_dir = state_dir.join("flagged");

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
            if !workspace_dir.join(".git").exists() {
                eprintln!(
                    "manual_sync_round: {} is not a git-seeded workspace directory yet -- \
                     build/launch the session first so the bind-mounted staging directory exists",
                    workspace_dir.display()
                );
                return ExitCode::FAILURE;
            }
            // Real edit every run, so this is never a no-op even when
            // re-run against an already-synced state dir.
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
                workspace_dir: &workspace_dir,
                patterns: &patterns,
                flagged_store: &store,
            };
            sync::sync_host_to_sandbox(&request, &runner, &audit)
        }
        "sandbox-to-host" => {
            let request = SandboxToHostRequest {
                project_root: &project_root,
                workspace_dir: &workspace_dir,
                patterns: &patterns,
                flagged_store: &store,
            };
            sync::sync_sandbox_to_host(&request, &runner, &audit)
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
