//! Adversarial coverage for content-based secrets scanning (Betterleaks):
//! can a project's own checked-in `betterleaks.toml` weaken or disable
//! detection? Two attempts, both required to fail per
//! `habitat_policy::secrets_scan`'s "additive, never a full replacement"
//! contract: a catch-all `[allowlist]` regex, and an empty ruleset (which
//! must not skip the unconditional baseline). `betterleaks` isn't
//! installed in this dev container, so attempt 2 is verified via the
//! fail-closed path: every file blocked regardless of ruleset content is
//! itself a meaningful confirmation that weakening the ruleset buys nothing.

use habitat_policy::config::ProjectConfig;
use habitat_policy::secrets_scan::{SecretsScanConfig, Toggle};
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::pipeline::{self, BuildError, BuildRequest};
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-adversarial-content-scan-ruleset-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A project `betterleaks.toml` with a catch-all allowlist regex must be
/// rejected before anything is staged.
#[test]
fn catch_all_allowlist_ruleset_is_rejected_before_anything_is_staged() {
    let project = temp_dir("catch-all");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    fs::write(
        project.join("betterleaks.toml"),
        "[allowlist]\nregexes = [\".*\"]\n",
    )
    .unwrap();
    let workdir = temp_dir("catch-all-workdir");

    let request = BuildRequest {
        project_root: &project,
        staging_dir: workdir.join("staging"),
        project_config: ProjectConfig {
            secrets_scan: SecretsScanConfig {
                content: Toggle::Enabled,
                ..Default::default()
            },
            ..Default::default()
        },
        content_ruleset_path: workdir.join("effective-betterleaks.toml"),
    };

    let result = pipeline::build(request, &SystemCommandRunner);
    assert!(
        matches!(result, Err(BuildError::ContentRules(_))),
        "a catch-all allowlist must hard-fail the build, not silently disable detection: {result:?}"
    );
    assert!(
        !workdir.join("staging").exists(),
        "nothing downstream of the rejected ruleset may exist"
    );
    assert!(!workdir.join("effective-betterleaks.toml").exists());

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
}

/// An empty project `betterleaks.toml` is not itself an error, but must
/// never be read as "skip the baseline too" -- the effective-ruleset
/// snapshot still carries the baseline, and the build still fails every
/// file closed since the scanner is genuinely absent here.
#[test]
fn empty_project_ruleset_cannot_be_used_to_skip_the_baseline() {
    let project = temp_dir("empty-ruleset");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    fs::write(project.join("betterleaks.toml"), "").unwrap();
    let workdir = temp_dir("empty-ruleset-workdir");

    let request = BuildRequest {
        project_root: &project,
        staging_dir: workdir.join("staging"),
        project_config: ProjectConfig {
            secrets_scan: SecretsScanConfig {
                content: Toggle::Enabled,
                ..Default::default()
            },
            ..Default::default()
        },
        content_ruleset_path: workdir.join("effective-betterleaks.toml"),
    };

    let outcome = pipeline::build(request, &SystemCommandRunner)
        .expect("an empty project ruleset is not itself an error");

    let effective = fs::read_to_string(workdir.join("effective-betterleaks.toml")).unwrap();
    assert!(
        effective.contains("id = \"generic-api-key\""),
        "the baseline must still be present in the effective ruleset"
    );
    assert!(
        !workdir.join("staging/main.rs").exists(),
        "with the scanner genuinely unavailable, the file must still be blocked, not silently \
         waved through because the project's own ruleset was empty"
    );
    // main.rs and betterleaks.toml itself -- both blocked, scanner unavailable.
    assert_eq!(outcome.staging_report.skipped_content_scan.len(), 2);

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
}
