//! Adversarial coverage for content-based secrets scanning (Betterleaks):
//! can a project's own checked-in `betterleaks.toml` be used to weaken or
//! fully disable detection? Lives here per `file-structure.md`/AGENTS.md
//! Section 6 ("adversarial tests cover... together"), alongside
//! `blocklist_disk_image.rs`.
//!
//! Two attempts, both required to fail per `habitat_policy::secrets_scan`'s
//! contract ("additive to Habitat's baseline rules, never a full
//! replacement... must not be able to fully disable detection"):
//! 1. A catch-all `[allowlist]` regex, which would suppress every
//!    finding (baseline included) if it were honored.
//! 2. An empty project ruleset, on the theory that "no rules" might mean
//!    "no baseline either" -- it must not; the baseline is unconditional.
//!
//! `betterleaks` isn't installed in this dev container (it isn't ordinary
//! tooling, unlike `git`/e2fsprogs -- see
//! `crates/install/src/checks.rs::betterleaks`), so attempt 2 is verified
//! through the fail-closed path instead of a real finding: since the
//! scanner is absent, every file is blocked regardless of ruleset content
//! -- which is itself still a meaningful adversarial confirmation
//! ("weakening the ruleset doesn't even get you a pass-through when the
//! scanner can't run at all").

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
/// rejected before anything is staged -- the same "hard stop before
/// staging exists" shape as the git-history-toggle exit gate.
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
        image_path: workdir.join("session.img"),
        image_size_mb: 16,
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

/// An empty project `betterleaks.toml` is not itself an error (it adds
/// nothing, which is fine) -- but it must never be read as "skip the
/// baseline too". The written effective-ruleset snapshot still carries
/// the baseline regardless, and (since `betterleaks` is genuinely absent
/// here) the build still fails every file closed rather than treating an
/// empty project ruleset as "nothing to enforce, let it all through".
#[test]
fn empty_project_ruleset_cannot_be_used_to_skip_the_baseline() {
    let project = temp_dir("empty-ruleset");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    fs::write(project.join("betterleaks.toml"), "").unwrap();
    let workdir = temp_dir("empty-ruleset-workdir");

    let request = BuildRequest {
        project_root: &project,
        staging_dir: workdir.join("staging"),
        image_path: workdir.join("session.img"),
        image_size_mb: 16,
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
    // Two files exist in the project (main.rs and its own betterleaks.toml,
    // which is scanned like any other ordinary file) -- both must be
    // blocked, since the scanner is genuinely unavailable.
    assert_eq!(outcome.staging_report.skipped_content_scan.len(), 2);

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
}
