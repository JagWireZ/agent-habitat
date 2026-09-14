//! Phase 2 exit-gate tests for `habitat-workspace` -- this crate's
//! contract with the rest of the system, not pure internal logic, so it
//! lives here per `file-structure.md` rather than inline in the crate.
//!
//! The blocklisted-files-never-on-disk-image adversarial requirement
//! lives in `tests/adversarial/blocklist_disk_image.rs` alongside Phase
//! 3/5's containment/egress adversarial tests, per file-structure.md's
//! "adversarial tests... live together" convention -- this file covers
//! the git-history-toggle exit-gate requirement plus a couple of
//! pipeline-level, whole-system checks that don't fit the "adversarial"
//! framing on their own.

use habitat_policy::config::ProjectConfig;
use habitat_policy::git_history::{GitHistoryApproval, GitHistoryConfig};
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::pipeline::{self, BuildError, BuildRequest};
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-workspace-exit-gate-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Exit gate: "git-history toggle defaults off, and flipping it without
/// a logged approval entry is blocked/flagged as a hard failure, not a
/// warning" -- verified through the actual pipeline entry point
/// (`pipeline::build`), not just the lower-level `git_history::resolve`
/// unit tests, so this is a true end-to-end confirmation of the
/// requirement.
#[test]
fn flipping_git_history_on_without_approval_hard_fails_the_whole_build_before_staging() {
    let project = temp_dir("project-unapproved");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    let workdir = temp_dir("workdir-unapproved");

    let request = BuildRequest {
        project_root: &project,
        staging_dir: workdir.join("staging"),
        image_path: workdir.join("session.img"),
        image_size_mb: 16,
        project_config: ProjectConfig {
            blocklist_additions: vec![],
            git_history: GitHistoryConfig {
                enabled: true,
                approval: None,
            },
        },
    };

    let result = pipeline::build(request, &SystemCommandRunner);
    assert!(
        matches!(result, Err(BuildError::GitHistory(_))),
        "expected a hard GitHistory error, got {result:?}"
    );
    // Nothing downstream of the failed toggle resolution may exist --
    // confirms this is a hard stop, not a degraded/partial build.
    assert!(!workdir.join("staging").exists());
    assert!(!workdir.join("session.img").exists());

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
}

/// The default-off counterpart: with no config at all, the pipeline
/// proceeds and seeds a synthetic repo, never real history.
#[test]
fn default_off_git_history_builds_a_synthetic_repo() {
    let project = temp_dir("project-default");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    let workdir = temp_dir("workdir-default");

    let request = BuildRequest {
        project_root: &project,
        staging_dir: workdir.join("staging"),
        image_path: workdir.join("session.img"),
        image_size_mb: 16,
        project_config: ProjectConfig::default(),
    };

    let outcome = pipeline::build(request, &SystemCommandRunner).unwrap();
    assert_eq!(
        outcome.git_history_mode,
        habitat_policy::git_history::GitHistoryMode::Synthetic
    );
    assert!(workdir.join("staging/.git").is_dir());

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
}

/// The properly-approved counterpart: a complete approval entry lets the
/// toggle actually take effect, sharing the real `.git` (read-only, per
/// `gitseed::copy_real_history_read_only`).
#[test]
fn approved_git_history_toggle_shares_real_history() {
    let project = temp_dir("project-approved");
    std::process::Command::new("git")
        .args(["init", "--quiet", project.to_str().unwrap()])
        .output()
        .unwrap();
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    let workdir = temp_dir("workdir-approved");

    let request = BuildRequest {
        project_root: &project,
        staging_dir: workdir.join("staging"),
        image_path: workdir.join("session.img"),
        image_size_mb: 16,
        project_config: ProjectConfig {
            blocklist_additions: vec![],
            git_history: GitHistoryConfig {
                enabled: true,
                approval: Some(GitHistoryApproval {
                    reviewed_by: "Jane Doe".to_string(),
                    date: "2026-09-14".to_string(),
                    reason: "team needs blame history".to_string(),
                }),
            },
        },
    };

    let outcome = pipeline::build(request, &SystemCommandRunner).unwrap();
    assert_eq!(
        outcome.git_history_mode,
        habitat_policy::git_history::GitHistoryMode::RealHistoryReadOnly
    );
    assert!(workdir.join("staging/.git/HEAD").exists());

    fs::remove_dir_all(&project).unwrap();
    let mut dir_perms = fs::metadata(&workdir).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    dir_perms.set_readonly(false);
    let _ = fs::set_permissions(&workdir, dir_perms);
    let _ = fs::remove_dir_all(&workdir);
}
