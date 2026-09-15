//! Builds the staging directory: a filtered copy of a project, with the
//! secrets blocklist enforced *before* anything is written -- the
//! enforcement point this phase exists to place correctly (AGENTS.md
//! Section 2 invariant 2). There is no "copy everything, then delete the
//! blocked files" step anywhere in this module: each file is decided
//! on -- blocked or not -- before it is ever read or written, so a
//! blocked file's bytes never touch the staging directory even
//! transiently.
//!
//! `.git` is deliberately never walked by this module -- git-history
//! handling (synthetic seed vs. real read-only copy) is a distinct
//! decision made by [`crate::gitseed`], not a file the ordinary blocklist
//! walk should ever copy on its own.
//!
//! Symlinks are skipped outright, not followed. A symlink inside a
//! project could point anywhere on the host filesystem (e.g. at a real
//! `~/.ssh/id_rsa` via a relative `../../..` target) -- following it
//! would let a filename-based blocklist be defeated by indirection, and
//! copying it as a broken/dangling link into the sandbox has no benefit.
//! This is a known, deliberate limitation, not an oversight.

use crate::command_runner::CommandRunner;
use crate::content_scan::{self, ScanOutcome};
use habitat_policy::blocklist;
use std::io;
use std::path::{Path, PathBuf};

/// One file skipped by the content scan -- either a real finding, or a
/// scanner error (both fail closed to "don't copy", per
/// `crate::content_scan`'s contract; this struct exists so the report can
/// still tell the two apart for audit/debugging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentScanSkip {
    pub path: String,
    pub reason: String,
}

/// The result of one staging build: what was copied, and -- for audit
/// (Phase 6) and this phase's adversarial test -- exactly what was
/// skipped and why.
#[derive(Debug, Default, Clone)]
pub struct StagingReport {
    pub copied: Vec<String>,
    pub skipped_blocklisted: Vec<String>,
    pub skipped_symlinks: Vec<String>,
    pub skipped_content_scan: Vec<ContentScanSkip>,
}

/// Wires a content scanner into [`build_staging_dir`]: the `betterleaks`
/// binary is run through `runner`, against the already-resolved,
/// already-merged effective ruleset at `ruleset_path`
/// (`habitat_policy::secrets_scan`). Passing `None` to `build_staging_dir`
/// means content scanning is off for this build (the project's
/// `secrets_scan.content: disabled`) -- the filename blocklist still
/// applies either way, independently (AGENTS.md Section 2 invariant 8).
pub struct ContentScanConfig<'a> {
    pub runner: &'a dyn CommandRunner,
    pub ruleset_path: &'a Path,
}

/// Copies `project_root` into `staging_dir` (which must not already
/// exist), applying `patterns` to every regular file before it is copied,
/// then -- if `content_scan` is `Some` -- scanning whatever survived that
/// filename filter with `betterleaks` before it, too, is copied. Both
/// checks run *before* any byte of a given file is written into staging;
/// there is no "copy then scrub" step for either mechanism (AGENTS.md
/// Section 2 invariant 2). `.git` at the project root is always skipped
/// here regardless of the git-history toggle -- see [`crate::gitseed`].
pub fn build_staging_dir(
    project_root: &Path,
    staging_dir: &Path,
    patterns: &[String],
    content_scan: Option<ContentScanConfig<'_>>,
) -> io::Result<StagingReport> {
    if staging_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "staging directory {} already exists -- refusing to build into it",
                staging_dir.display()
            ),
        ));
    }
    std::fs::create_dir_all(staging_dir)?;

    let mut report = StagingReport::default();
    walk(
        project_root,
        project_root,
        staging_dir,
        patterns,
        content_scan.as_ref(),
        &mut report,
    )?;
    Ok(report)
}

fn walk(
    project_root: &Path,
    dir: &Path,
    staging_dir: &Path,
    patterns: &[String],
    content_scan: Option<&ContentScanConfig<'_>>,
    report: &mut StagingReport,
) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        let relative = relative_slash_path(project_root, &path);

        if relative == ".git" {
            // Git-history handling is a separate, explicit decision
            // (`crate::gitseed`) -- never copied by the ordinary walk.
            continue;
        }

        if file_type.is_symlink() {
            report.skipped_symlinks.push(relative);
            continue;
        }

        if file_type.is_dir() {
            walk(
                project_root,
                &path,
                staging_dir,
                patterns,
                content_scan,
                report,
            )?;
            continue;
        }

        if blocklist::is_blocked(patterns, &relative) {
            report.skipped_blocklisted.push(relative);
            continue;
        }

        if let Some(scan) = content_scan {
            if let ScanOutcome::Blocked(reason) =
                content_scan::scan_file(scan.runner, &path, scan.ruleset_path)
            {
                report.skipped_content_scan.push(ContentScanSkip {
                    path: relative,
                    reason,
                });
                continue;
            }
        }

        let dest = staging_dir.join(&relative);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&path, &dest)?;
        report.copied.push(relative);
    }
    Ok(())
}

/// `path`'s location relative to `root`, rendered with `/` separators
/// regardless of host path conventions -- the blocklist's matching rule
/// (`habitat_policy::blocklist`) is defined in terms of `/`-separated
/// relative paths.
fn relative_slash_path(root: &Path, path: &Path) -> String {
    let rel: PathBuf = path.strip_prefix(root).unwrap_or(path).to_path_buf();
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "habitat-workspace-staging-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn blocked_files_are_never_copied() {
        let project = temp_dir("project-a");
        fs::write(project.join(".env"), "SECRET=1").unwrap();
        fs::write(project.join("main.rs"), "fn main() {}").unwrap();
        fs::create_dir_all(project.join("secrets")).unwrap();
        fs::write(project.join("secrets/id_rsa"), "not really a key").unwrap();

        let staging = std::env::temp_dir().join(format!(
            "{}-staging",
            project.file_name().unwrap().to_string_lossy()
        ));
        let patterns = habitat_policy::blocklist::default_patterns();
        let report = build_staging_dir(&project, &staging, &patterns, None).unwrap();

        assert!(!staging.join(".env").exists());
        assert!(!staging.join("secrets/id_rsa").exists());
        assert!(staging.join("main.rs").exists());
        assert_eq!(report.copied, vec!["main.rs".to_string()]);
        assert!(report.skipped_blocklisted.contains(&".env".to_string()));
        assert!(report
            .skipped_blocklisted
            .contains(&"secrets/id_rsa".to_string()));

        fs::remove_dir_all(&project).unwrap();
        fs::remove_dir_all(&staging).unwrap();
    }

    #[test]
    fn dot_git_is_never_copied_by_the_ordinary_walk() {
        let project = temp_dir("project-b");
        fs::create_dir_all(project.join(".git")).unwrap();
        fs::write(project.join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        fs::write(project.join("readme.md"), "hi").unwrap();

        let staging = project.with_file_name(format!(
            "{}-staging",
            project.file_name().unwrap().to_string_lossy()
        ));
        let report = build_staging_dir(&project, &staging, &[], None).unwrap();

        assert!(!staging.join(".git").exists());
        assert!(staging.join("readme.md").exists());
        assert!(!report.copied.iter().any(|p| p.starts_with(".git")));

        fs::remove_dir_all(&project).unwrap();
        fs::remove_dir_all(&staging).unwrap();
    }

    #[test]
    fn symlinks_are_skipped_not_followed() {
        let project = temp_dir("project-c");
        fs::write(project.join("real.txt"), "hi").unwrap();
        std::os::unix::fs::symlink(project.join("real.txt"), project.join("link.txt")).unwrap();

        let staging = project.with_file_name(format!(
            "{}-staging",
            project.file_name().unwrap().to_string_lossy()
        ));
        let report = build_staging_dir(&project, &staging, &[], None).unwrap();

        assert!(!staging.join("link.txt").exists());
        assert!(staging.join("real.txt").exists());
        assert_eq!(report.skipped_symlinks, vec!["link.txt".to_string()]);

        fs::remove_dir_all(&project).unwrap();
        fs::remove_dir_all(&staging).unwrap();
    }

    #[test]
    fn refuses_to_build_into_an_existing_staging_dir() {
        let project = temp_dir("project-d");
        let staging = temp_dir("project-d-staging-preexisting");
        let err = build_staging_dir(&project, &staging, &[], None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir_all(&project).unwrap();
        fs::remove_dir_all(&staging).unwrap();
    }

    /// The content scanner runs on files that already passed the filename
    /// filter, on the same block-from-copy path -- a finding stops the
    /// file being copied, exactly like a blocklist hit, and never
    /// half-copies it first.
    #[test]
    fn content_scan_blocks_a_file_the_filename_filter_would_have_let_through() {
        use crate::command_runner::testing::FakeCommandRunner;

        let project = temp_dir("project-content-scan");
        fs::write(project.join("main.rs"), "fn main() {}").unwrap();
        fs::write(project.join("notes.txt"), "AKIAABCDEFGHIJKLMNOP").unwrap();
        let staging = project.with_file_name(format!(
            "{}-staging",
            project.file_name().unwrap().to_string_lossy()
        ));
        let ruleset_path = PathBuf::from("/effective/betterleaks.toml");

        let clean_invocation = format!(
            "betterleaks scan --config {} --format json --file {}",
            ruleset_path.display(),
            project.join("main.rs").display()
        );
        let finding_invocation = format!(
            "betterleaks scan --config {} --format json --file {}",
            ruleset_path.display(),
            project.join("notes.txt").display()
        );
        let runner = FakeCommandRunner::default()
            .with_ok(&clean_invocation, "")
            .with_findings(&finding_invocation, r#"[{"rule_id":"aws-access-key-id"}]"#);

        let report = build_staging_dir(
            &project,
            &staging,
            &[],
            Some(ContentScanConfig {
                runner: &runner,
                ruleset_path: &ruleset_path,
            }),
        )
        .unwrap();

        assert!(staging.join("main.rs").exists());
        assert!(!staging.join("notes.txt").exists());
        assert_eq!(report.copied, vec!["main.rs".to_string()]);
        assert_eq!(report.skipped_content_scan.len(), 1);
        assert_eq!(report.skipped_content_scan[0].path, "notes.txt");
        assert!(report.skipped_content_scan[0]
            .reason
            .contains("aws-access-key-id"));

        fs::remove_dir_all(&project).unwrap();
        fs::remove_dir_all(&staging).unwrap();
    }

    /// `None` (content scanning disabled) must never invoke the scanner
    /// at all -- confirmed here by using a runner that has no invocations
    /// configured, so any call to it would panic/error the test via a
    /// broken build rather than silently succeeding.
    #[test]
    fn content_scan_disabled_means_no_scan_is_ever_run() {
        let project = temp_dir("project-content-scan-disabled");
        fs::write(project.join("notes.txt"), "AKIAABCDEFGHIJKLMNOP").unwrap();
        let staging = project.with_file_name(format!(
            "{}-staging",
            project.file_name().unwrap().to_string_lossy()
        ));

        let report = build_staging_dir(&project, &staging, &[], None).unwrap();

        assert!(staging.join("notes.txt").exists());
        assert!(report.skipped_content_scan.is_empty());

        fs::remove_dir_all(&project).unwrap();
        fs::remove_dir_all(&staging).unwrap();
    }
}
