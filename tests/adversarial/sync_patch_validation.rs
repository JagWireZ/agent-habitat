//! Phase 4 adversarial tests for `habitat-workspace::sync`
//! (`tmp/wip/implementation-plan.md`): the host->sandbox counterparts to
//! `tests/unit/workspace/sync_exit_gate.rs`'s sandbox->host cases, plus a
//! source-level check that this crate's sync mechanism never reaches the
//! user's real remote (`AGENTS.md` Section 2, invariant 4).
//!
//! Wired into `cargo test` via the `[[test]]` target in
//! `crates/workspace/Cargo.toml`, alongside `blocklist_disk_image.rs` and
//! `content_scan_ruleset_tamper.rs`.

use habitat_audit::{EventKind, MemoryAuditSink};
use habitat_policy::blocklist;
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::guest_exec::GuestEndpoint;
use habitat_workspace::sync::{
    self, FlagReason, FlaggedPatchStore, HostToSandboxRequest, SyncOutcome,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Both tests below resolve as `NoOp`/`Flagged` before ever touching the
/// guest (that's the whole point -- a blocklisted or ruleset-touching
/// change must never even reach it), so this endpoint is never actually
/// dialed; its values are placeholders, not exercised.
fn unused_guest_endpoint() -> GuestEndpoint<'static> {
    GuestEndpoint {
        addr: "unused",
        private_key_path: Path::new("/unused"),
    }
}

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

/// Adversarial case: a project adds a genuinely new file that happens to
/// match the blocklist (e.g. a developer drops a fresh `.env` into their
/// working directory mid-session), with no other change alongside it.
/// The host->sandbox side must never generate, let alone apply, a patch
/// for it -- the same blocklist filter the initial disk build uses
/// (`crate::staging::build_staging_dir`) is re-applied at snapshot-refresh
/// time, before any diff is produced, so `.env` never reaches the
/// host-side mirror, never appears in a patch, and no guest interaction
/// is ever attempted for it (`AGENTS.md` Section 2, invariant 2). This is
/// a stronger guarantee than "caught by a re-check after the fact": there
/// is no window in which `.env`'s bytes are ever diffed at all.
#[test]
fn host_to_sandbox_never_lets_a_newly_added_blocklisted_file_reach_the_guest() {
    let project = temp_dir("h2s-smuggle-project");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    let mirror = temp_dir("h2s-smuggle-mirror");
    fs::remove_dir_all(&mirror).unwrap();
    fs::create_dir_all(&mirror).unwrap();
    fs::write(mirror.join("main.rs"), "fn main() {}").unwrap();
    git_init_committed(&mirror);

    // A secret file appears on the host side after the initial build --
    // the only change since the last sync.
    fs::write(project.join(".env"), "SECRET=leaked").unwrap();

    let flagged_dir = temp_dir("h2s-smuggle-flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);
    let patterns = blocklist::default_patterns();
    let request = HostToSandboxRequest {
        project_root: &project,
        mirror_dir: &mirror,
        guest: unused_guest_endpoint(),
        patterns: &patterns,
        flagged_store: &store,
    };
    // Real `SystemCommandRunner` throughout, for both host_runner and
    // guest_runner -- since `.env` is the only change and it's filtered
    // out before any diff exists, this sync must resolve as a true
    // no-op, meaning `ssh` (present on this machine, but pointed at a
    // guest address that was never actually launched) is never invoked.
    // If the code ever tried to reach the guest here, that real `ssh`
    // call against an unreachable address would fail the test loudly.
    let runner = SystemCommandRunner;
    let audit = MemoryAuditSink::default();

    let outcome = sync::sync_host_to_sandbox(&request, &runner, &runner, &audit).unwrap();
    assert_eq!(
        outcome,
        SyncOutcome::NoOp,
        ".env must never even produce a patch to flag -- it's filtered out before the diff"
    );
    assert!(
        !mirror.join(".env").exists(),
        ".env must never even reach the host-side mirror of the guest's tree"
    );
    assert!(audit.events.lock().unwrap().is_empty());

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&mirror).unwrap();
    fs::remove_dir_all(&flagged_dir).unwrap();
}

/// Adversarial case: a `betterleaks.toml` edit on the host side must be
/// flagged (never silently merged into the guest's governing snapshot),
/// per `docs/decisions/0007-content-secrets-scan-snapshot.md`.
#[test]
fn host_to_sandbox_flags_a_betterleaks_toml_edit_and_emits_the_distinct_audit_event() {
    let project = temp_dir("h2s-ruleset-project");
    fs::write(project.join("betterleaks.toml"), "# original\n").unwrap();
    let mirror = temp_dir("h2s-ruleset-mirror");
    fs::remove_dir_all(&mirror).unwrap();
    fs::create_dir_all(&mirror).unwrap();
    fs::write(mirror.join("betterleaks.toml"), "# original\n").unwrap();
    git_init_committed(&mirror);

    fs::write(project.join("betterleaks.toml"), "# widened allowlist\n").unwrap();

    let flagged_dir = temp_dir("h2s-ruleset-flagged");
    let store = FlaggedPatchStore::new(&flagged_dir);
    let request = HostToSandboxRequest {
        project_root: &project,
        mirror_dir: &mirror,
        guest: unused_guest_endpoint(),
        patterns: &[],
        flagged_store: &store,
    };
    let runner = SystemCommandRunner;
    let audit = MemoryAuditSink::default();

    let outcome = sync::sync_host_to_sandbox(&request, &runner, &runner, &audit).unwrap();
    match &outcome {
        SyncOutcome::Flagged { reason, .. } => {
            assert_eq!(reason, &FlagReason::ContentRulesetMidSessionEdit);
        }
        other => panic!("expected Flagged, got {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(mirror.join("betterleaks.toml")).unwrap(),
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
    fs::remove_dir_all(&mirror).unwrap();
    fs::remove_dir_all(&flagged_dir).unwrap();
}

/// Contract-level check (same posture as `containment_escape.rs` for
/// `habitat-vm`): this crate's sync mechanism must contain no code path
/// that pushes, or configures a remote, for either the guest's or the
/// host mirror's git repo -- `AGENTS.md` Section 2, invariant 4. Grepping
/// the source is a deliberately blunt, easy-to-keep-honest check: it errs
/// on the side of false alarms (e.g. flags an innocent comment
/// mentioning "remote") rather than missing a real regression.
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
