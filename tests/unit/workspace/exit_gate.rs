//! Exit-gate tests for `habitat-workspace`'s pipeline-level contract:
//! the git-history-toggle requirement plus a few whole-system checks. The
//! blocklisted-files adversarial requirement lives separately in
//! `tests/adversarial/blocklist_disk_image.rs`.

use habitat_policy::config::ProjectConfig;
use habitat_policy::git_history::{GitHistoryApproval, GitHistoryConfig};
use habitat_policy::secrets_scan::{SecretsScanConfig, Toggle};
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::pipeline::{self, BuildError, BuildRequest};
use std::fs;
use std::path::PathBuf;

/// These git-history-toggle tests aren't about content scanning, so they
/// disable it explicitly rather than depending on a binary that may not
/// be installed (`betterleaks` isn't guaranteed present in CI).
fn content_scan_disabled() -> SecretsScanConfig {
    SecretsScanConfig {
        content: Toggle::Disabled,
        ..Default::default()
    }
}

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

/// Flipping git-history on without a logged approval entry must hard-fail
/// the build, verified through the actual pipeline entry point.
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
            secrets_scan: content_scan_disabled(),
            resource_limits: Default::default(),
            egress_allowlist_additions: vec![],
        },
        content_ruleset_path: workdir.join("effective-betterleaks.toml"),
    };

    let result = pipeline::build(request, &SystemCommandRunner);
    assert!(
        matches!(result, Err(BuildError::GitHistory(_))),
        "expected a hard GitHistory error, got {result:?}"
    );
    // A hard stop -- nothing downstream of the failure may exist.
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
        project_config: ProjectConfig {
            secrets_scan: content_scan_disabled(),
            ..Default::default()
        },
        content_ruleset_path: workdir.join("effective-betterleaks.toml"),
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

/// A complete approval entry lets the toggle take effect, sharing the
/// real `.git` read-only.
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
            secrets_scan: content_scan_disabled(),
            resource_limits: Default::default(),
            egress_allowlist_additions: vec![],
        },
        content_ruleset_path: workdir.join("effective-betterleaks.toml"),
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
