//! Black-box exit-gate tests for `habitat-workspace::sync`, run through
//! `sync::sync_host_to_sandbox`/`sync_sandbox_to_host` as `habitat run`'s
//! prompt loop would call them. `git` runs for real via
//! `SystemCommandRunner`; the guest side is faked via `FakeCommandRunner`
//! (`ssh`, per `docs/decisions/0008-guest-exec-channel.md` -- `podman
//! exec`/`podman cp` were confirmed not to work against `krun`). The
//! "no background sync daemon" half of this exit gate needs a real
//! running session; see `tests/manual/validate-sync.sh`.

use habitat_audit::{EventKind, MemoryAuditSink};
use habitat_policy::blocklist;
use habitat_workspace::command_runner::testing::FakeCommandRunner;
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::guest_exec::{ssh_exec_args, GuestEndpoint};
use habitat_workspace::sync::{
    self, FlagReason, FlaggedPatchStore, HostToSandboxRequest, SandboxToHostRequest, SyncOutcome,
    GUEST_WORKSPACE_DIR,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const GUEST_HOST: &str = "127.0.0.1";
const GUEST_PORT: u16 = 34567;
const GUEST_KEY_PATH: &str = "/tmp/habitat-sync-exit-gate-key";

fn guest_endpoint() -> GuestEndpoint<'static> {
    GuestEndpoint {
        host: GUEST_HOST,
        port: GUEST_PORT,
        private_key_path: Path::new(GUEST_KEY_PATH),
    }
}

/// Builds the `ssh ...` invocation string to key a `FakeCommandRunner`
/// against, via the same construction the real runner uses -- never a
/// hand-typed copy that could drift from the real argv.
fn ssh_invocation(env: &[(&str, &str)], program: &str, args: &[&str]) -> String {
    let full = ssh_exec_args(&guest_endpoint(), env, program, args);
    format!("ssh {}", full.join(" "))
}

const SYNC_IDENTITY_ENV: [(&str, &str); 4] = [
    ("GIT_AUTHOR_NAME", "Agent Habitat"),
    ("GIT_AUTHOR_EMAIL", "sandbox@agent-habitat.invalid"),
    ("GIT_COMMITTER_NAME", "Agent Habitat"),
    ("GIT_COMMITTER_EMAIL", "sandbox@agent-habitat.invalid"),
];

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-sync-exit-gate-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn git_init_committed(dir: &std::path::Path) {
    let d = dir.to_str().unwrap();
    Command::new("git")
        .args(["-C", d, "init", "--quiet"])
        .output()
        .unwrap();
    Command::new("git")
        .args(["-C", d, "add", "-A"])
        .env("GIT_AUTHOR_NAME", "Agent Habitat")
        .env("GIT_AUTHOR_EMAIL", "sandbox@agent-habitat.invalid")
        .output()
        .unwrap();
    Command::new("git")
        .args(["-C", d, "commit", "--quiet", "--allow-empty", "-m", "seed"])
        .env("GIT_AUTHOR_NAME", "Agent Habitat")
        .env("GIT_AUTHOR_EMAIL", "sandbox@agent-habitat.invalid")
        .env("GIT_COMMITTER_NAME", "Agent Habitat")
        .env("GIT_COMMITTER_EMAIL", "sandbox@agent-habitat.invalid")
        .output()
        .unwrap();
}

/// Host->sandbox: no guest invocation is configured on the fake runner, so
/// any attempt to reach the guest would fail the test.
#[test]
fn host_to_sandbox_no_op_when_nothing_changed() {
    let project = temp_dir("h2s-noop-project");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    let mirror = temp_dir("h2s-noop-mirror");
    fs::remove_dir_all(&mirror).unwrap();
    fs::create_dir_all(&mirror).unwrap();
    fs::write(mirror.join("main.rs"), "fn main() {}").unwrap();
    git_init_committed(&mirror);

    let store = FlaggedPatchStore::new(temp_dir("h2s-noop-flagged"));
    let request = HostToSandboxRequest {
        project_root: &project,
        mirror_dir: &mirror,
        guest: guest_endpoint(),
        patterns: &[],
        flagged_store: &store,
    };
    let runner = SystemCommandRunner;
    let audit = MemoryAuditSink::default();

    let outcome = sync::sync_host_to_sandbox(&request, &runner, &runner, &audit).unwrap();
    assert_eq!(outcome, SyncOutcome::NoOp);
    assert!(
        audit.events.lock().unwrap().is_empty(),
        "a no-op sync must not emit any audit event"
    );

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&mirror).unwrap();
}

/// Sandbox->host: `git status --porcelain` reporting clean must stop
/// everything there -- no commit, no diff, no host mutation.
#[test]
fn sandbox_to_host_no_op_when_guest_reports_clean() {
    let project = temp_dir("s2h-noop-project");
    let mirror = temp_dir("s2h-noop-mirror");
    let store = FlaggedPatchStore::new(temp_dir("s2h-noop-flagged"));

    let runner = FakeCommandRunner::default().with_ok(
        &ssh_invocation(
            &[],
            "git",
            &["-C", GUEST_WORKSPACE_DIR, "status", "--porcelain"],
        ),
        "",
    );
    let audit = MemoryAuditSink::default();
    let request = SandboxToHostRequest {
        project_root: &project,
        mirror_dir: &mirror,
        guest: guest_endpoint(),
        patterns: &[],
        flagged_store: &store,
    };

    let outcome = sync::sync_sandbox_to_host(&request, &runner, &runner, &audit).unwrap();
    assert_eq!(outcome, SyncOutcome::NoOp);
    assert!(audit.events.lock().unwrap().is_empty());
    // No commit/diff invocation must have happened beyond the status check.
    let invocations = runner.invocations.borrow();
    assert_eq!(invocations.len(), 1);

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&mirror).unwrap();
}

/// A corrupted/malformed patch must be flagged, not applied -- simulated
/// via a fake guest that reports a dirty tree and hands back garbage.
#[test]
fn sandbox_to_host_flags_a_malformed_patch_instead_of_applying_it() {
    let project = temp_dir("s2h-malformed-project");
    fs::write(project.join("real.txt"), "original\n").unwrap();
    let mirror = temp_dir("s2h-malformed-mirror");
    let flagged_dir = temp_dir("s2h-malformed-flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);

    let runner = FakeCommandRunner::default()
        .with_ok(
            &ssh_invocation(
                &[],
                "git",
                &["-C", GUEST_WORKSPACE_DIR, "status", "--porcelain"],
            ),
            " M real.txt\n",
        )
        .with_ok(
            &ssh_invocation(
                &SYNC_IDENTITY_ENV,
                "git",
                &["-C", GUEST_WORKSPACE_DIR, "add", "-A"],
            ),
            "",
        )
        .with_ok(
            &ssh_invocation(
                &SYNC_IDENTITY_ENV,
                "git",
                &[
                    "-C",
                    GUEST_WORKSPACE_DIR,
                    "commit",
                    "--quiet",
                    "-m",
                    "habitat sync",
                ],
            ),
            "",
        )
        .with_ok(
            &ssh_invocation(
                &[],
                "git",
                &["-C", GUEST_WORKSPACE_DIR, "diff", "HEAD~1", "HEAD"],
            ),
            "this is not a real unified diff -- just noise\n",
        );
    let audit = MemoryAuditSink::default();
    let request = SandboxToHostRequest {
        project_root: &project,
        mirror_dir: &mirror,
        guest: guest_endpoint(),
        patterns: &[],
        flagged_store: &store,
    };

    // The structural check runs for real against the project directory.
    let host_runner = SystemCommandRunner;
    let outcome = sync::sync_sandbox_to_host(&request, &host_runner, &runner, &audit).unwrap();
    match &outcome {
        SyncOutcome::Flagged { reason, .. } => {
            assert!(matches!(reason, FlagReason::MalformedPatch(_)));
        }
        other => panic!("expected Flagged, got {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(project.join("real.txt")).unwrap(),
        "original\n",
        "a flagged patch must never be applied to the real host working directory"
    );
    let events = audit.events.lock().unwrap();
    assert!(events.iter().any(|e| e.kind == EventKind::SyncFlagged));

    let flagged_files: Vec<_> = fs::read_dir(&flagged_dir).unwrap().collect();
    assert!(
        !flagged_files.is_empty(),
        "a flagged patch must be persisted for review, not silently dropped"
    );

    fs::remove_dir_all(&project).unwrap();
    let _ = fs::remove_dir_all(&mirror);
    fs::remove_dir_all(&flagged_dir).unwrap();
}

/// A crafted patch attempting to smuggle a blocklisted file back in must
/// be caught by the re-check.
#[test]
fn sandbox_to_host_flags_a_patch_reintroducing_a_blocklisted_file() {
    let project = temp_dir("s2h-smuggle-project");
    let mirror = temp_dir("s2h-smuggle-mirror");
    let flagged_dir = temp_dir("s2h-smuggle-flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);
    let patterns = blocklist::default_patterns();

    let smuggled_patch = "diff --git a/.env b/.env\n\
new file mode 100644\n\
index 0000000..1111111\n\
--- /dev/null\n\
+++ b/.env\n\
@@ -0,0 +1 @@\n\
+SECRET=smuggled\n";
    let runner = FakeCommandRunner::default()
        .with_ok(
            &ssh_invocation(
                &[],
                "git",
                &["-C", GUEST_WORKSPACE_DIR, "status", "--porcelain"],
            ),
            "?? .env\n",
        )
        .with_ok(
            &ssh_invocation(
                &SYNC_IDENTITY_ENV,
                "git",
                &["-C", GUEST_WORKSPACE_DIR, "add", "-A"],
            ),
            "",
        )
        .with_ok(
            &ssh_invocation(
                &SYNC_IDENTITY_ENV,
                "git",
                &[
                    "-C",
                    GUEST_WORKSPACE_DIR,
                    "commit",
                    "--quiet",
                    "-m",
                    "habitat sync",
                ],
            ),
            "",
        )
        .with_ok(
            &ssh_invocation(
                &[],
                "git",
                &["-C", GUEST_WORKSPACE_DIR, "diff", "HEAD~1", "HEAD"],
            ),
            smuggled_patch,
        );
    let audit = MemoryAuditSink::default();
    let request = SandboxToHostRequest {
        project_root: &project,
        mirror_dir: &mirror,
        guest: guest_endpoint(),
        patterns: &patterns,
        flagged_store: &store,
    };

    let outcome = sync::sync_sandbox_to_host(&request, &runner, &runner, &audit).unwrap();
    match &outcome {
        SyncOutcome::Flagged { reason, .. } => match reason {
            FlagReason::BlocklistedPathReintroduced(paths) => {
                assert_eq!(paths, &vec![".env".to_string()]);
            }
            other => panic!("expected BlocklistedPathReintroduced, got {other:?}"),
        },
        other => panic!("expected Flagged, got {other:?}"),
    }
    assert!(
        !project.join(".env").exists(),
        "a smuggled blocklisted file must never reach the real host working directory"
    );

    fs::remove_dir_all(&project).unwrap();
    let _ = fs::remove_dir_all(&mirror);
    fs::remove_dir_all(&flagged_dir).unwrap();
}

/// Sync latency measured against a large-file-count fixture with real
/// recorded numbers -- any scale beyond what's measured here is a known
/// limitation, not an assertion.
#[test]
fn sync_perf_is_measured_against_a_monorepo_scale_fixture_with_real_numbers() {
    let project = temp_dir("perf-monorepo-project");
    const FILE_COUNT: usize = 2_000;
    for i in 0..FILE_COUNT {
        let dir = project.join(format!("pkg-{}", i % 50));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("file-{i}.rs")),
            format!("// file {i}\nfn f() {{}}\n"),
        )
        .unwrap();
    }

    let mirror = temp_dir("perf-monorepo-mirror");
    fs::remove_dir_all(&mirror).unwrap();
    fs::create_dir_all(&mirror).unwrap();
    // Exact copy so the first sync round measures detection, not application.
    fn copy_recursive(src: &std::path::Path, dest: &std::path::Path) {
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let to = dest.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                fs::create_dir_all(&to).unwrap();
                copy_recursive(&entry.path(), &to);
            } else {
                fs::copy(entry.path(), &to).unwrap();
            }
        }
    }
    copy_recursive(&project, &mirror);
    git_init_committed(&mirror);

    let store = FlaggedPatchStore::new(temp_dir("perf-flagged"));
    let request = HostToSandboxRequest {
        project_root: &project,
        mirror_dir: &mirror,
        guest: guest_endpoint(),
        patterns: &[],
        flagged_store: &store,
    };
    let runner = SystemCommandRunner;
    let audit = MemoryAuditSink::default();

    let start = std::time::Instant::now();
    let outcome = sync::sync_host_to_sandbox(&request, &runner, &runner, &audit).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(
        outcome,
        SyncOutcome::NoOp,
        "identical trees must detect as no-op"
    );
    eprintln!(
        "[sync perf] {FILE_COUNT} files, no-op host->sandbox detection: {:?} \
         (validated at this scale; not asserted beyond it -- see \
         tmp/wip/implementation-plan.md Phase 4 exit gate)",
        elapsed
    );
    // Generous bound so this is a regression guard, not a flaky timing test.
    assert!(
        elapsed.as_secs() < 30,
        "host->sandbox no-op detection over {FILE_COUNT} files took {:?}, \
         far beyond what's recorded as validated",
        elapsed
    );

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&mirror).unwrap();
}

/// The large-binary counterpart to the fixture above -- byte-copying cost
/// scales differently than walk/diff cost, so it's measured separately.
#[test]
fn sync_perf_is_measured_against_a_large_binary_fixture_with_real_numbers() {
    let project = temp_dir("perf-binary-project");
    const BINARY_FILE_COUNT: usize = 5;
    const BINARY_FILE_MB: usize = 20;
    let payload = vec![0xABu8; BINARY_FILE_MB * 1024 * 1024];
    for i in 0..BINARY_FILE_COUNT {
        fs::write(project.join(format!("asset-{i}.bin")), &payload).unwrap();
    }

    let mirror = temp_dir("perf-binary-mirror");
    fs::remove_dir_all(&mirror).unwrap();
    fs::create_dir_all(&mirror).unwrap();
    for i in 0..BINARY_FILE_COUNT {
        fs::copy(
            project.join(format!("asset-{i}.bin")),
            mirror.join(format!("asset-{i}.bin")),
        )
        .unwrap();
    }
    git_init_committed(&mirror);

    let store = FlaggedPatchStore::new(temp_dir("perf-binary-flagged"));
    let request = HostToSandboxRequest {
        project_root: &project,
        mirror_dir: &mirror,
        guest: guest_endpoint(),
        patterns: &[],
        flagged_store: &store,
    };
    let runner = SystemCommandRunner;
    let audit = MemoryAuditSink::default();

    let start = std::time::Instant::now();
    let outcome = sync::sync_host_to_sandbox(&request, &runner, &runner, &audit).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(
        outcome,
        SyncOutcome::NoOp,
        "identical binary trees must detect as no-op"
    );
    eprintln!(
        "[sync perf] {BINARY_FILE_COUNT} x {BINARY_FILE_MB}MB binary files, no-op \
         host->sandbox detection: {:?} (validated at this scale; not asserted \
         beyond it -- see tmp/wip/implementation-plan.md Phase 4 exit gate)",
        elapsed
    );
    assert!(
        elapsed.as_secs() < 30,
        "host->sandbox no-op detection over {BINARY_FILE_COUNT}x{BINARY_FILE_MB}MB \
         binaries took {:?}, far beyond what's recorded as validated",
        elapsed
    );

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&mirror).unwrap();
}

/// Regression test: applying a sandbox->host patch that creates a new file
/// must actually land it in `project_root`, even when `project_root` sits
/// inside another, unrelated git repository -- not just report `Applied`
/// while `git apply` silently skips it because it found that outer repo's
/// toplevel instead. Deliberately builds `project_root` inside a real
/// nested repo rather than the usual bare `temp_dir()`, since `/tmp` has
/// no enclosing repo and would never have caught this.
#[test]
fn sandbox_to_host_applies_a_new_file_even_when_project_root_is_nested_in_another_repo() {
    // Simulate an unrelated enclosing repository.
    let outer_repo = temp_dir("nested-outer-repo");
    git_init_committed(&outer_repo);
    let project = outer_repo.join("some").join("nested").join("project");
    fs::create_dir_all(&project).unwrap();
    // project_root deliberately has no .git of its own.
    assert!(!project.join(".git").exists());

    let mirror = temp_dir("nested-mirror");
    git_init_committed(&mirror);
    let flagged_dir = temp_dir("nested-flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);

    let new_file_patch = "diff --git a/from-guest.txt b/from-guest.txt\n\
new file mode 100644\n\
index 0000000..1111111\n\
--- /dev/null\n\
+++ b/from-guest.txt\n\
@@ -0,0 +1 @@\n\
+hello from the guest\n";

    let runner = FakeCommandRunner::default()
        .with_ok(
            &ssh_invocation(
                &[],
                "git",
                &["-C", GUEST_WORKSPACE_DIR, "status", "--porcelain"],
            ),
            "?? from-guest.txt\n",
        )
        .with_ok(
            &ssh_invocation(
                &SYNC_IDENTITY_ENV,
                "git",
                &["-C", GUEST_WORKSPACE_DIR, "add", "-A"],
            ),
            "",
        )
        .with_ok(
            &ssh_invocation(
                &SYNC_IDENTITY_ENV,
                "git",
                &[
                    "-C",
                    GUEST_WORKSPACE_DIR,
                    "commit",
                    "--quiet",
                    "-m",
                    "habitat sync",
                ],
            ),
            "",
        )
        .with_ok(
            &ssh_invocation(
                &[],
                "git",
                &["-C", GUEST_WORKSPACE_DIR, "diff", "HEAD~1", "HEAD"],
            ),
            new_file_patch,
        );
    let audit = MemoryAuditSink::default();
    let request = SandboxToHostRequest {
        project_root: &project,
        mirror_dir: &mirror,
        guest: guest_endpoint(),
        patterns: &[],
        flagged_store: &store,
    };

    // Only the guest side is faked; the apply runs for real against `project`.
    let host_runner = SystemCommandRunner;
    let outcome = sync::sync_sandbox_to_host(&request, &host_runner, &runner, &audit).unwrap();

    match &outcome {
        SyncOutcome::Applied { touched_paths, .. } => {
            assert_eq!(touched_paths, &vec!["from-guest.txt".to_string()]);
        }
        other => panic!("expected Applied, got {other:?}"),
    }

    // Without the fix, `outcome` would already claim Applied above while
    // this file silently never existed.
    assert_eq!(
        fs::read_to_string(project.join("from-guest.txt")).unwrap(),
        "hello from the guest\n",
        "an 'Applied' outcome must mean the file actually landed in \
         project_root, even when project_root sits inside an unrelated \
         enclosing git repository"
    );

    fs::remove_dir_all(&outer_repo).unwrap();
    fs::remove_dir_all(&mirror).unwrap();
    fs::remove_dir_all(&flagged_dir).unwrap();
}
