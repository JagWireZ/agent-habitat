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

use habitat_policy::blocklist;
use std::io;
use std::path::{Path, PathBuf};

/// The result of one staging build: what was copied, and -- for audit
/// (Phase 6) and this phase's adversarial test -- exactly what was
/// skipped and why.
#[derive(Debug, Default, Clone)]
pub struct StagingReport {
    pub copied: Vec<String>,
    pub skipped_blocklisted: Vec<String>,
    pub skipped_symlinks: Vec<String>,
}

/// Copies `project_root` into `staging_dir` (which must not already
/// exist), applying `patterns` to every regular file before it is copied.
/// `.git` at the project root is always skipped here regardless of the
/// git-history toggle -- see [`crate::gitseed`].
pub fn build_staging_dir(
    project_root: &Path,
    staging_dir: &Path,
    patterns: &[String],
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
        &mut report,
    )?;
    Ok(report)
}

fn walk(
    project_root: &Path,
    dir: &Path,
    staging_dir: &Path,
    patterns: &[String],
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
            walk(project_root, &path, staging_dir, patterns, report)?;
            continue;
        }

        if blocklist::is_blocked(patterns, &relative) {
            report.skipped_blocklisted.push(relative);
            continue;
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
        let report = build_staging_dir(&project, &staging, &patterns).unwrap();

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
        let report = build_staging_dir(&project, &staging, &[]).unwrap();

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
        let report = build_staging_dir(&project, &staging, &[]).unwrap();

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
        let err = build_staging_dir(&project, &staging, &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir_all(&project).unwrap();
        fs::remove_dir_all(&staging).unwrap();
    }
}
