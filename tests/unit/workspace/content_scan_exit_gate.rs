//! Content-based secrets scanning (Betterleaks) exit-gate tests for
//! `habitat-workspace`'s pipeline, confirming staging's per-file
//! scan-routing holds end to end through `pipeline::build`.
//!
//! `betterleaks` isn't guaranteed present in this dev container or CI, so
//! this file takes two approaches: tests observing "skipped"/"failed
//! closed" run against the real, genuinely-absent binary via
//! `SystemCommandRunner`; the one test needing an actual finding installs
//! a small stub `betterleaks` script onto `PATH` so the real shelling-out
//! contract (`--file`, exit codes) is genuinely exercised.

use habitat_policy::config::ProjectConfig;
use habitat_policy::secrets_scan::{SecretsScanConfig, Toggle};
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::pipeline::{self, BuildRequest};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// Serializes the test that mutates the process-global PATH env var, since
// cargo runs a crate's tests in multiple threads of the same process.
static PATH_ENV_LOCK: Mutex<()> = Mutex::new(());

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-workspace-content-scan-exit-gate-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn default_request<'a>(project: &'a Path, workdir: &Path, content: Toggle) -> BuildRequest<'a> {
    BuildRequest {
        project_root: project,
        staging_dir: workdir.join("staging"),
        image_path: workdir.join("session.img"),
        image_size_mb: 16,
        project_config: ProjectConfig {
            secrets_scan: SecretsScanConfig {
                content,
                ..Default::default()
            },
            ..Default::default()
        },
        content_ruleset_path: workdir.join("effective-betterleaks.toml"),
    }
}

/// Content scanning respects the disabled flag -- a suspicious-looking
/// file is still staged when `secrets_scan.content: disabled`, and no
/// ruleset snapshot is written.
#[test]
fn disabled_flag_skips_content_scanning_entirely() {
    // Shares the lock with the stub-betterleaks test: this test's
    // assertions assume betterleaks is genuinely absent from PATH.
    let _guard = PATH_ENV_LOCK.lock().unwrap();
    let project = temp_dir("disabled");
    fs::write(project.join("notes.txt"), "AKIAABCDEFGHIJKLMNOP").unwrap();
    let workdir = temp_dir("disabled-workdir");

    let request = default_request(&project, &workdir, Toggle::Disabled);
    let outcome = pipeline::build(request, &SystemCommandRunner).unwrap();

    assert!(workdir.join("staging/notes.txt").exists());
    assert!(outcome.staging_report.skipped_content_scan.is_empty());
    assert!(
        !workdir.join("effective-betterleaks.toml").exists(),
        "no ruleset snapshot should be written when content scanning is off"
    );

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
}

/// Fails closed on scanner error -- with content scanning enabled but
/// `betterleaks` not installed, every file must be blocked from copy.
#[test]
fn enabled_flag_fails_closed_when_betterleaks_is_not_installed() {
    let _guard = PATH_ENV_LOCK.lock().unwrap();
    let project = temp_dir("missing-scanner");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    let workdir = temp_dir("missing-scanner-workdir");

    let request = default_request(&project, &workdir, Toggle::Enabled);
    let outcome = pipeline::build(request, &SystemCommandRunner).unwrap();

    assert!(
        !workdir.join("staging/main.rs").exists(),
        "a file must not be copied when it couldn't actually be scanned"
    );
    assert_eq!(outcome.staging_report.skipped_content_scan.len(), 1);
    assert_eq!(
        outcome.staging_report.skipped_content_scan[0].path,
        "main.rs"
    );
    assert!(outcome.staging_report.skipped_content_scan[0]
        .reason
        .contains("could not run betterleaks"));

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
}

/// Confirms the effective ruleset written for this build merges the
/// bundled baseline with the project's own `betterleaks.toml` -- additive,
/// both present, neither replacing the other.
#[test]
fn effective_ruleset_snapshot_merges_baseline_with_project_rules() {
    let _guard = PATH_ENV_LOCK.lock().unwrap();
    let project = temp_dir("merge");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    fs::write(
        project.join("betterleaks.toml"),
        "[[rules]]\nid = \"project-custom-rule-marker\"\n",
    )
    .unwrap();
    let workdir = temp_dir("merge-workdir");

    let request = default_request(&project, &workdir, Toggle::Enabled);
    // Only the ruleset snapshot matters here; betterleaks is still absent.
    pipeline::build(request, &SystemCommandRunner).unwrap();

    let effective = fs::read_to_string(workdir.join("effective-betterleaks.toml")).unwrap();
    assert!(
        effective.contains("id = \"generic-api-key\""),
        "baseline rules must still be present"
    );
    assert!(
        effective.contains("project-custom-rule-marker"),
        "the project's own rule must be merged in"
    );

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
}

/// Writes a small, real, executable `betterleaks` stub to a fresh temp
/// directory: reads the `--file` argument, reports one finding (exit 1)
/// if that file's contents contain `SECRET_FINDING_MARKER`, otherwise
/// exits 0 with no output. Returns the directory it was written into, so
/// the caller can prepend it to `PATH`.
fn write_stub_betterleaks() -> PathBuf {
    let dir = temp_dir("stub-betterleaks-bin");
    let script = dir.join("betterleaks");
    fs::write(
        &script,
        "#!/bin/sh\n\
         file=\"\"\n\
         prev=\"\"\n\
         for arg in \"$@\"; do\n\
         \x20\x20if [ \"$prev\" = \"--file\" ]; then file=\"$arg\"; fi\n\
         \x20\x20prev=\"$arg\"\n\
         done\n\
         if grep -q SECRET_FINDING_MARKER \"$file\" 2>/dev/null; then\n\
         \x20\x20echo '[{\"rule_id\":\"stub-test-rule\"}]'\n\
         \x20\x20exit 1\n\
         fi\n\
         exit 0\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(&script, perms).unwrap();
    dir
}

/// With a stub `betterleaks` on `PATH`, a file carrying the finding marker
/// is blocked from copy while an unrelated file is staged normally.
#[test]
fn content_scan_blocks_only_the_file_with_a_real_finding() {
    let _guard = PATH_ENV_LOCK.lock().unwrap();
    let stub_dir = write_stub_betterleaks();
    let original_path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{}", stub_dir.display(), original_path));

    let project = temp_dir("real-finding");
    fs::write(project.join("main.rs"), "fn main() {}").unwrap();
    fs::write(project.join("leaky.txt"), "token=SECRET_FINDING_MARKER").unwrap();
    let workdir = temp_dir("real-finding-workdir");

    let request = default_request(&project, &workdir, Toggle::Enabled);
    let result = pipeline::build(request, &SystemCommandRunner);

    std::env::set_var("PATH", original_path);
    let outcome = result.unwrap();

    assert!(workdir.join("staging/main.rs").exists());
    assert!(!workdir.join("staging/leaky.txt").exists());
    assert_eq!(outcome.staging_report.skipped_content_scan.len(), 1);
    assert_eq!(
        outcome.staging_report.skipped_content_scan[0].path,
        "leaky.txt"
    );
    assert!(outcome.staging_report.skipped_content_scan[0]
        .reason
        .contains("stub-test-rule"));

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
    fs::remove_dir_all(&stub_dir).unwrap();
}
