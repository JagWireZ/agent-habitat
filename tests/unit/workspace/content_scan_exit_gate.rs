//! Content-based secrets scanning (Betterleaks) exit-gate tests for
//! `habitat-workspace`'s pipeline -- this crate's contract with the rest
//! of the system, not pure internal logic, so it lives here per
//! `file-structure.md` rather than inline in the crate (staging's own
//! per-file scan-routing is unit-tested directly in
//! `crates/workspace/src/staging.rs`'s inline tests; this file confirms
//! the same behavior holds end to end through `pipeline::build`, plus the
//! enabled/disabled-flag and ruleset-merge requirements that only make
//! sense at this level).
//!
//! `betterleaks` isn't ordinary tooling guaranteed present in this dev
//! container or CI (unlike `git`/e2fsprogs, which Phase 2's tests already
//! established run for real here) -- that's exactly why
//! `crates/install/src/checks.rs::betterleaks` exists as its own
//! preflight check. So this file takes two different, deliberate
//! approaches rather than assuming a real `betterleaks` install:
//! - Tests that only need to observe "scanning was skipped" or "scanning
//!   failed closed" run against the *real*, genuinely-absent binary via
//!   `SystemCommandRunner` -- an honest, unmocked demonstration of the
//!   fail-closed behavior this feature's whole point is to guarantee.
//! - The one test that needs an actual finding (or a controlled clean
//!   result) installs a small stub `betterleaks` script onto `PATH` for
//!   its own duration -- a real subprocess with real argv parsing, not a
//!   canned in-memory match table, so the actual shelling-out contract
//!   (`--config`, `--format json`, `--file`, exit codes) is genuinely
//!   exercised end to end.

use habitat_policy::config::ProjectConfig;
use habitat_policy::secrets_scan::{SecretsScanConfig, Toggle};
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::pipeline::{self, BuildRequest};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// `install_stub_betterleaks`/`restore_path` mutate the process-global
// `PATH` env var, and cargo runs a crate's tests in multiple threads of
// the same process by default -- serialize the one test that needs this,
// same reasoning as `habitat-workspace`'s own `GIT_IDENTITY_ENV_LOCK`.
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

/// Exit gate: content scanning respects the disabled flag -- a file that
/// would otherwise look suspicious (an AWS-shaped access key) is still
/// staged when `secrets_scan.content: disabled`, and no ruleset snapshot
/// is even written, since there's nothing to scan against.
#[test]
fn disabled_flag_skips_content_scanning_entirely() {
    // Shares `PATH_ENV_LOCK` with the stub-`betterleaks`-on-`PATH` test
    // below even though this test doesn't touch `PATH` itself: cargo runs
    // a crate's tests in multiple threads of the same process by
    // default, and this test's assertions assume `betterleaks` is
    // genuinely absent -- which wouldn't hold if it ran concurrently
    // with the window where that other test has prepended a stub to
    // `PATH`.
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

/// Exit gate: fails closed on scanner error -- with content scanning
/// enabled (the default) but `betterleaks` genuinely not installed on
/// this machine, every file must be blocked from copy, never silently
/// let through unscanned.
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
    // betterleaks is still absent, so every file is blocked (covered by
    // the test above) -- this test only cares about the snapshot file
    // pipeline::build writes before staging runs.
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

/// Exit gate: "content scan runs on the right files" -- with a real
/// (stub) `betterleaks` on `PATH`, a file carrying the finding marker is
/// blocked from copy while an unrelated file is staged normally.
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
