//! Top-level orchestration for Phase 2's disk-build pipeline: project
//! copy -> blocklist filter -> git-history seed -> disk image assembly.
//! This is the entry point Phase 7's `habitat run` calls into; it just
//! sequences the other modules in this crate rather than reimplementing
//! any of their logic.
//!
//! Order matters and is fixed: the git-history toggle is resolved
//! *before* anything is staged, so an invalid/unapproved toggle stops
//! the whole build before the staging directory (let alone the disk
//! image) is ever created -- consistent with "no code path where an
//! excluded file/state ever touches the sandbox disk, even transiently"
//! extended to the git-history decision, not just individual files.

use crate::command_runner::CommandRunner;
use crate::diskimage::{self, DiskImageError};
use crate::gitseed::{self, GitSeedError};
use crate::staging::{self, StagingReport};
use habitat_policy::blocklist;
use habitat_policy::config::ProjectConfig;
use habitat_policy::git_history::{self, GitHistoryError, GitHistoryMode};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    GitHistory(GitHistoryError),
    Staging(String),
    GitSeed(GitSeedError),
    DiskImage(DiskImageError),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::GitHistory(e) => write!(f, "{e}"),
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
}

/// What the build actually did, for the caller to log (Phase 6) or
/// inspect (this phase's tests).
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

    let patterns = blocklist::effective_patterns(&request.project_config.blocklist_additions);
    let staging_report =
        staging::build_staging_dir(request.project_root, &request.staging_dir, &patterns)
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
