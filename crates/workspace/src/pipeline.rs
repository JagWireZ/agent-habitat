//! Top-level orchestration for the disk-build pipeline: project copy ->
//! blocklist filter -> git-history seed -> disk image assembly. Just
//! sequences the other modules in this crate.
//!
//! Order is fixed: the git-history toggle is resolved *before* anything
//! is staged, so an invalid/unapproved toggle stops the whole build
//! before the staging directory is ever created.

use crate::command_runner::CommandRunner;
use crate::diskimage::{self, DiskImageError};
use crate::gitseed::{self, GitSeedError};
use crate::staging::{self, ContentScanConfig, StagingReport};
use habitat_policy::blocklist;
use habitat_policy::config::ProjectConfig;
use habitat_policy::git_history::{self, GitHistoryError, GitHistoryMode};
use habitat_policy::secrets_scan::{self, ContentRulesError};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    GitHistory(GitHistoryError),
    ContentRules(ContentRulesError),
    ContentRulesWrite(String),
    Staging(String),
    GitSeed(GitSeedError),
    DiskImage(DiskImageError),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::GitHistory(e) => write!(f, "{e}"),
            BuildError::ContentRules(e) => write!(f, "{e}"),
            BuildError::ContentRulesWrite(msg) => write!(f, "content-scan ruleset: {msg}"),
            BuildError::Staging(msg) => write!(f, "staging: {msg}"),
            BuildError::GitSeed(e) => write!(f, "{e}"),
            BuildError::DiskImage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Everything needed to build one session's disk from one project.
pub struct BuildRequest<'a> {
    pub project_root: &'a Path,
    pub staging_dir: PathBuf,
    pub image_path: PathBuf,
    pub image_size_mb: u64,
    pub project_config: ProjectConfig,
    /// Where to write this build's resolved, merged content-scan ruleset
    /// (see `habitat_policy::secrets_scan::load_effective_ruleset`). Only
    /// written/consulted when `project_config.secrets_scan.content` is
    /// enabled. This is a session-start snapshot -- `crate::sync` reuses
    /// it rather than re-resolving from a possibly-edited on-disk
    /// `betterleaks.toml` (`docs/decisions/0007-content-secrets-scan-snapshot.md`).
    pub content_ruleset_path: PathBuf,
}

/// What the build actually did, for the caller to log or inspect.
#[derive(Debug, Clone)]
pub struct BuildOutcome {
    pub git_history_mode: GitHistoryMode,
    pub staging_report: StagingReport,
    pub image_path: PathBuf,
}

/// Runs the full pipeline. Fails closed at the first failing stage --
/// nothing downstream of a failed stage runs (in particular: if the
/// git-history toggle doesn't resolve, no staging directory is created
/// at all).
pub fn build<R: CommandRunner>(
    request: BuildRequest<'_>,
    runner: &R,
) -> Result<BuildOutcome, BuildError> {
    let git_history_mode = git_history::resolve(&request.project_config.git_history)
        .map_err(BuildError::GitHistory)?;

    // Disabling the filename blocklist is an explicit, visible opt-out
    // (empty pattern set), never the default.
    let patterns = if request.project_config.secrets_scan.filenames.is_enabled() {
        blocklist::effective_patterns(&request.project_config.blocklist_additions)
    } else {
        Vec::new()
    };

    // Resolve and write the effective ruleset snapshot before staging
    // runs -- an invalid/unmergeable ruleset must stop the whole build.
    let content_scan_enabled = request.project_config.secrets_scan.content.is_enabled();
    let content_scan_config = if content_scan_enabled {
        let effective_ruleset = secrets_scan::load_effective_ruleset(
            request.project_root,
            request
                .project_config
                .secrets_scan
                .content_rules_path
                .as_deref(),
        )
        .map_err(BuildError::ContentRules)?;
        std::fs::write(&request.content_ruleset_path, effective_ruleset).map_err(|e| {
            BuildError::ContentRulesWrite(format!(
                "could not write effective ruleset to {}: {e}",
                request.content_ruleset_path.display()
            ))
        })?;
        Some(ContentScanConfig {
            runner,
            ruleset_path: &request.content_ruleset_path,
        })
    } else {
        None
    };

    let staging_report = staging::build_staging_dir(
        request.project_root,
        &request.staging_dir,
        &patterns,
        content_scan_config,
    )
    .map_err(|e| BuildError::Staging(e.to_string()))?;

    match git_history_mode {
        GitHistoryMode::Synthetic => {
            gitseed::seed_synthetic(&request.staging_dir, runner).map_err(BuildError::GitSeed)?;
        }
        GitHistoryMode::RealHistoryReadOnly => {
            gitseed::copy_real_history_read_only(request.project_root, &request.staging_dir)
                .map_err(BuildError::GitSeed)?;
        }
    }

    diskimage::assemble_disk_image(
        &request.staging_dir,
        &request.image_path,
        request.image_size_mb,
        runner,
    )
    .map_err(BuildError::DiskImage)?;

    Ok(BuildOutcome {
        git_history_mode,
        staging_report,
        image_path: request.image_path.clone(),
    })
}
