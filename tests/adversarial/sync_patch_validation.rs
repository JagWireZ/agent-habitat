//! Adversarial tests for `habitat-workspace::sync`: the host->sandbox
//! counterparts to `tests/unit/workspace/sync_exit_gate.rs`'s sandbox->host
//! cases, plus a source-level check that sync never reaches the user's real
//! remote (`AGENTS.md` Section 2, invariant 4).

use habitat_audit::{EventKind, MemoryAuditSink};
use habitat_policy::blocklist;
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::sync::{
    self, FlagReason, FlaggedPatchStore, HostToSandboxRequest, SyncOutcome,
};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-sync-adversarial-{name}-{}-{}",
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
        .args(["-C", d, "config", "gc.auto", "0"])
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

/// A newly added file matching the blocklist (e.g. a `.env` dropped in
/// mid-session) must never reach the shared workspace directory or appear
/// in a patch -- the blocklist filter is re-applied at scratch-snapshot
/// time, before any diff is produced, so its bytes are never even diffed
/// (`AGENTS.md` Section 2, invariant 2).
#[test]
fn host_to_sandbox_never_lets_a_newly_added_blocklisted_file_reach_the_workspace_dir() {
    let project = temp_dir("h2s-smuggle-project");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    let workspace = temp_dir("h2s-smuggle-workspace");
    fs::remove_dir_all(&workspace).unwrap();
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("main.rs"), "fn main() {}").unwrap();
    git_init_committed(&workspace);

    fs::write(project.join(".env"), "SECRET=leaked").unwrap();

    let flagged_dir = temp_dir("h2s-smuggle-flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);
    let patterns = blocklist::default_patterns();
    let request = HostToSandboxRequest {
        project_root: &project,
        workspace_dir: &workspace,
        patterns: &patterns,
        flagged_store: &store,
    };
    let runner = SystemCommandRunner;
    let audit = MemoryAuditSink::default();

    let outcome = sync::sync_host_to_sandbox(&request, &runner, &audit).unwrap();
    assert_eq!(
        outcome,
        SyncOutcome::NoOp,
        ".env must never even produce a patch to flag -- it's filtered out before the diff"
    );
    assert!(
        !workspace.join(".env").exists(),
        ".env must never even reach the shared workspace directory the guest has bind-mounted"
    );
    assert!(audit.events.lock().unwrap().is_empty());

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workspace).unwrap();
    fs::remove_dir_all(&flagged_dir).unwrap();
}

/// A `betterleaks.toml` edit on the host side must be flagged, never
/// silently merged into the guest's governing snapshot
/// (`0007-content-secrets-scan-snapshot.md`).
#[test]
fn host_to_sandbox_flags_a_betterleaks_toml_edit_and_emits_the_distinct_audit_event() {
    let project = temp_dir("h2s-ruleset-project");
    fs::write(project.join("betterleaks.toml"), "# original\n").unwrap();
    let workspace = temp_dir("h2s-ruleset-workspace");
    fs::remove_dir_all(&workspace).unwrap();
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("betterleaks.toml"), "# original\n").unwrap();
    git_init_committed(&workspace);

    fs::write(project.join("betterleaks.toml"), "# widened allowlist\n").unwrap();

    let flagged_dir = temp_dir("h2s-ruleset-flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);
    let request = HostToSandboxRequest {
        project_root: &project,
        workspace_dir: &workspace,
        patterns: &[],
        flagged_store: &store,
    };
    let runner = SystemCommandRunner;
    let audit = MemoryAuditSink::default();

    let outcome = sync::sync_host_to_sandbox(&request, &runner, &audit).unwrap();
    match &outcome {
        SyncOutcome::Flagged { reason, .. } => {
            assert_eq!(reason, &FlagReason::ContentRulesetMidSessionEdit);
        }
        other => panic!("expected Flagged, got {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(workspace.join("betterleaks.toml")).unwrap(),
        "# original\n",
        "the governing ruleset snapshot must never be updated as a side effect of a flagged patch"
    );
    let events = audit.events.lock().unwrap();
    assert!(events.iter().any(|e| e.kind == EventKind::SyncFlagged));
    assert!(
        events
            .iter()
            .any(|e| e.kind == EventKind::ContentRulesetMidSessionEdit),
        "a betterleaks.toml-touching patch must emit the distinct event in ADDITION to SyncFlagged"
    );

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workspace).unwrap();
    fs::remove_dir_all(&flagged_dir).unwrap();
}

/// Sync must contain no code path that pushes or configures a remote for
/// either repo (`AGENTS.md` Section 2, invariant 4). Grepping the source is
/// deliberately blunt -- false alarms are fine, a missed regression isn't.
#[test]
fn sync_source_never_invokes_git_push_or_configures_a_remote() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sync_src = manifest_dir.join("src/sync.rs");
    let contents = fs::read_to_string(&sync_src)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", sync_src.display()));
    for forbidden in ["\"push\"", "\"remote\"", "git push", "remote add"] {
        assert!(
            !contents.contains(forbidden),
            "found {forbidden:?} in crates/workspace/src/sync.rs -- the sandbox must never \
             push or configure a remote (AGENTS.md Section 2, invariant 4)"
        );
    }
}
