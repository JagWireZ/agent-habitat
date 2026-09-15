//! Phase 4 exit-gate tests for `habitat-workspace::sync`
//! (`tmp/wip/implementation-plan.md`).
//!
//! Per `file-structure.md` Section 2, these are black-box tests of this
//! crate's contract with the rest of the system -- run through
//! `sync::sync_host_to_sandbox`/`sync::sync_sandbox_to_host` exactly as a
//! later phase's `habitat run` prompt loop would call them -- so they
//! live here under `tests/unit/workspace/`, wired in via the `[[test]]`
//! target in `crates/workspace/Cargo.toml`.
//!
//! `git` is ordinary, always-available tooling (like `crate::gitseed`'s
//! own tests) -- exercised for real via `SystemCommandRunner` throughout.
//! The one genuinely KVM/live-session-dependent half of this phase's exit
//! gate -- "a live-session process inventory confirms no continuous/
//! background sync daemon exists beyond the two discrete invocations" --
//! needs an actually-running session, so it's `tests/manual/
//! validate-sync.sh`'s job instead; everything here uses
//! `FakeCommandRunner` to stand in for the guest side (`podman
//! exec`/`podman cp`), which is exactly the seam `habitat-vm`'s own tests
//! use for the same reason.

use habitat_audit::{EventKind, MemoryAuditSink};
use habitat_policy::blocklist;
use habitat_vm::session::SessionId;
use habitat_workspace::command_runner::testing::FakeCommandRunner;
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::sync::{
    self, FlagReason, FlaggedPatchStore, HostToSandboxRequest, SandboxToHostRequest, SyncOutcome,
    GUEST_WORKSPACE_DIR,
};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

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

/// Exit gate: "nothing happens when nothing changed" -- host->sandbox
/// side. No guest invocation is configured on the fake runner at all, so
/// any attempt to reach the guest would fail the test via a broken
/// `Result`, not silently succeed.
#[test]
fn host_to_sandbox_no_op_when_nothing_changed() {
    let project = temp_dir("h2s-noop-project");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    let mirror = temp_dir("h2s-noop-mirror");
    fs::remove_dir_all(&mirror).unwrap();
    fs::create_dir_all(&mirror).unwrap();
    fs::write(mirror.join("main.rs"), "fn main() {}").unwrap();
    git_init_committed(&mirror);

    let session_id = SessionId::from_name("habitat-sync-noop").unwrap();
    let store = FlaggedPatchStore::new(temp_dir("h2s-noop-flagged"));
    let request = HostToSandboxRequest {
        project_root: &project,
        mirror_dir: &mirror,
        session_id: &session_id,
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

/// Exit gate: "nothing happens when nothing changed" -- sandbox->host
/// side. `git status --porcelain` reporting clean must stop everything
/// right there -- no commit, no diff, no host mutation.
#[test]
fn sandbox_to_host_no_op_when_guest_reports_clean() {
    let project = temp_dir("s2h-noop-project");
    let mirror = temp_dir("s2h-noop-mirror");
    let session_id = SessionId::from_name("habitat-sync-s2h-noop").unwrap();
    let store = FlaggedPatchStore::new(temp_dir("s2h-noop-flagged"));

    let runner = FakeCommandRunner::default().with_ok(
        &format!(
            "podman exec habitat-sync-s2h-noop git -C {GUEST_WORKSPACE_DIR} status --porcelain"
        ),
        "",
    );
    let audit = MemoryAuditSink::default();
    let request = SandboxToHostRequest {
        project_root: &project,
        mirror_dir: &mirror,
        session_id: &session_id,
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

/// Exit gate: "injecting a corrupted/malformed patch ... is flagged, not
/// applied" -- sandbox->host direction, simulated via a fake guest that
/// reports a dirty tree and hands back garbage as its "diff".
#[test]
fn sandbox_to_host_flags_a_malformed_patch_instead_of_applying_it() {
    let project = temp_dir("s2h-malformed-project");
    fs::write(project.join("real.txt"), "original\n").unwrap();
    let mirror = temp_dir("s2h-malformed-mirror");
    let session_id = SessionId::from_name("habitat-sync-s2h-malformed").unwrap();
    let flagged_dir = temp_dir("s2h-malformed-flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);

    let name = "habitat-sync-s2h-malformed";
    let runner = FakeCommandRunner::default()
        .with_ok(
            &format!("podman exec {name} git -C {GUEST_WORKSPACE_DIR} status --porcelain"),
            " M real.txt\n",
        )
        .with_ok(
            &format!(
                "podman exec --env GIT_AUTHOR_NAME=Agent Habitat --env GIT_AUTHOR_EMAIL=sandbox@agent-habitat.invalid --env GIT_COMMITTER_NAME=Agent Habitat --env GIT_COMMITTER_EMAIL=sandbox@agent-habitat.invalid {name} git -C {GUEST_WORKSPACE_DIR} add -A"
            ),
            "",
        )
        .with_ok(
            &format!(
                "podman exec --env GIT_AUTHOR_NAME=Agent Habitat --env GIT_AUTHOR_EMAIL=sandbox@agent-habitat.invalid --env GIT_COMMITTER_NAME=Agent Habitat --env GIT_COMMITTER_EMAIL=sandbox@agent-habitat.invalid {name} git -C {GUEST_WORKSPACE_DIR} commit --quiet -m habitat sync"
            ),
            "",
        )
        .with_ok(
            &format!("podman exec {name} git -C {GUEST_WORKSPACE_DIR} diff HEAD~1 HEAD"),
            "this is not a real unified diff -- just noise\n",
        );
    let audit = MemoryAuditSink::default();
    let request = SandboxToHostRequest {
        project_root: &project,
        mirror_dir: &mirror,
        session_id: &session_id,
        patterns: &[],
        flagged_store: &store,
    };

    // The structural check (`git apply --check`) must run for real
    // against the real project directory -- `SystemCommandRunner` here,
    // distinct from the faked guest-exec channel above.
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

/// Exit gate: "a crafted sync patch attempting to smuggle a blocklisted
/// file back in is caught by the re-check" -- sandbox->host direction.
#[test]
fn sandbox_to_host_flags_a_patch_reintroducing_a_blocklisted_file() {
    let project = temp_dir("s2h-smuggle-project");
    let mirror = temp_dir("s2h-smuggle-mirror");
    let session_id = SessionId::from_name("habitat-sync-s2h-smuggle").unwrap();
    let flagged_dir = temp_dir("s2h-smuggle-flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);
    let patterns = blocklist::default_patterns();

    let name = "habitat-sync-s2h-smuggle";
    let smuggled_patch = "diff --git a/.env b/.env\n\
new file mode 100644\n\
index 0000000..1111111\n\
--- /dev/null\n\
+++ b/.env\n\
@@ -0,0 +1 @@\n\
+SECRET=smuggled\n";
    let runner = FakeCommandRunner::default()
        .with_ok(
            &format!("podman exec {name} git -C {GUEST_WORKSPACE_DIR} status --porcelain"),
            "?? .env\n",
        )
        .with_ok(
            &format!(
                "podman exec --env GIT_AUTHOR_NAME=Agent Habitat --env GIT_AUTHOR_EMAIL=sandbox@agent-habitat.invalid --env GIT_COMMITTER_NAME=Agent Habitat --env GIT_COMMITTER_EMAIL=sandbox@agent-habitat.invalid {name} git -C {GUEST_WORKSPACE_DIR} add -A"
            ),
            "",
        )
        .with_ok(
            &format!(
                "podman exec --env GIT_AUTHOR_NAME=Agent Habitat --env GIT_AUTHOR_EMAIL=sandbox@agent-habitat.invalid --env GIT_COMMITTER_NAME=Agent Habitat --env GIT_COMMITTER_EMAIL=sandbox@agent-habitat.invalid {name} git -C {GUEST_WORKSPACE_DIR} commit --quiet -m habitat sync"
            ),
            "",
        )
        .with_ok(
            &format!("podman exec {name} git -C {GUEST_WORKSPACE_DIR} diff HEAD~1 HEAD"),
            smuggled_patch,
        );
    let audit = MemoryAuditSink::default();
    let request = SandboxToHostRequest {
        project_root: &project,
        mirror_dir: &mirror,
        session_id: &session_id,
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

/// Sync latency/throughput measured against a large-file-count fixture,
/// with real recorded numbers -- per the exit gate, "any scale beyond
/// what's measured is logged as a known limitation, not asserted as
/// fine." This measures the host-side half of a host->sandbox round
/// (staging refresh + git diff), the part that scales with the size of
/// the real project on disk, using real `git` throughout.
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
    // Seed the mirror as an exact copy so the first sync round is a
    // genuine no-op measurement (detection cost, not application cost).
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

    let session_id = SessionId::from_name("habitat-sync-perf").unwrap();
    let store = FlaggedPatchStore::new(temp_dir("perf-flagged"));
    let request = HostToSandboxRequest {
        project_root: &project,
        mirror_dir: &mirror,
        session_id: &session_id,
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
    // Recorded, generous bound so this stays a real regression guard, not
    // a flaky timing assertion -- the number above is what's actually
    // "validated at this scale" for the run-book, not this assertion.
    assert!(
        elapsed.as_secs() < 30,
        "host->sandbox no-op detection over {FILE_COUNT} files took {:?}, \
         far beyond what's recorded as validated",
        elapsed
    );

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&mirror).unwrap();
}

/// The large-binary-fixture half of the same perf requirement -- a
/// monorepo of many small text files stresses the walk/diff cost, a
/// handful of large binary files stresses the byte-copying cost
/// differently, so both are recorded separately rather than assuming one
/// stands in for the other.
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

    let session_id = SessionId::from_name("habitat-sync-perf-binary").unwrap();
    let store = FlaggedPatchStore::new(temp_dir("perf-binary-flagged"));
    let request = HostToSandboxRequest {
        project_root: &project,
        mirror_dir: &mirror,
        session_id: &session_id,
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
