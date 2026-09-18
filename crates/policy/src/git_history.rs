//! The git-history toggle: synthetic repo by default, real `.git` shared
//! read-only only when a project's config turns that on with a logged,
//! reviewed approval already present -- otherwise resolution is a hard
//! failure, never a silent pass-through.
//!
//! This module only resolves *whether* real history is permitted; the
//! disk-build pipeline (`crates/workspace`) acts on the result.

use std::fmt;

/// What the disk-build pipeline should do about git history for this
/// session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitHistoryMode {
    /// Default: seed a brand-new, synthetic repo with no real history.
    Synthetic,
    /// The project's config turned the toggle on, with a valid logged
    /// approval already present -- share the real `.git`, read-only.
    RealHistoryReadOnly,
}

/// The project-level toggle as read from its checked-in config. `enabled`
/// alone is not sufficient to turn real history on -- see [`resolve`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitHistoryConfig {
    pub enabled: bool,
    pub approval: Option<GitHistoryApproval>,
}

/// The logged, reviewed entry required before a git-history-toggle flip
/// takes effect. All three fields are required and must be non-empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitHistoryApproval {
    pub reviewed_by: String,
    pub date: String,
    pub reason: String,
}

impl GitHistoryApproval {
    fn is_complete(&self) -> bool {
        !self.reviewed_by.trim().is_empty()
            && !self.date.trim().is_empty()
            && !self.reason.trim().is_empty()
    }
}

/// Why real history was refused. No "warning" or "degraded mode" variant --
/// resolution either produces a mode or fails closed to `Synthetic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHistoryError {
    pub message: String,
}

impl fmt::Display for GitHistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "git-history toggle: {}", self.message)
    }
}

impl std::error::Error for GitHistoryError {}

/// Resolves a project's git-history config into a mode, or a hard error.
///
/// `enabled: false` always resolves to `Synthetic` regardless of any
/// `approval` present -- a stale approval from a reverted flip must never
/// silently re-enable real history. `enabled: true` requires a complete
/// approval to resolve to `RealHistoryReadOnly`; a missing or incomplete
/// one is a hard `Err`, never a fallback or warning-only pass-through.
pub fn resolve(config: &GitHistoryConfig) -> Result<GitHistoryMode, GitHistoryError> {
    if !config.enabled {
        return Ok(GitHistoryMode::Synthetic);
    }
    match &config.approval {
        Some(approval) if approval.is_complete() => Ok(GitHistoryMode::RealHistoryReadOnly),
        Some(_) => Err(GitHistoryError {
            message: "enabled, but the logged approval entry is incomplete (reviewed_by, date, \
                      and reason are all required) -- refusing to expose real git history"
                .to_string(),
        }),
        None => Err(GitHistoryError {
            message: "enabled, but no logged approval entry is present -- flipping this toggle \
                      on requires a reviewed entry before it takes effect"
                .to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_off_resolves_synthetic() {
        let config = GitHistoryConfig::default();
        assert_eq!(resolve(&config), Ok(GitHistoryMode::Synthetic));
    }

    #[test]
    fn off_with_a_stale_approval_still_resolves_synthetic() {
        let config = GitHistoryConfig {
            enabled: false,
            approval: Some(GitHistoryApproval {
                reviewed_by: "Jane".to_string(),
                date: "2026-01-01".to_string(),
                reason: "old flip, since reverted".to_string(),
            }),
        };
        assert_eq!(resolve(&config), Ok(GitHistoryMode::Synthetic));
    }

    #[test]
    fn on_with_missing_approval_is_a_hard_error() {
        let config = GitHistoryConfig {
            enabled: true,
            approval: None,
        };
        let err = resolve(&config).unwrap_err();
        assert!(err.message.contains("no logged approval"));
    }

    #[test]
    fn on_with_incomplete_approval_is_a_hard_error() {
        let config = GitHistoryConfig {
            enabled: true,
            approval: Some(GitHistoryApproval {
                reviewed_by: "Jane".to_string(),
                date: String::new(),
                reason: "needed for blame".to_string(),
            }),
        };
        let err = resolve(&config).unwrap_err();
        assert!(err.message.contains("incomplete"));
    }

    #[test]
    fn on_with_complete_approval_resolves_real_history() {
        let config = GitHistoryConfig {
            enabled: true,
            approval: Some(GitHistoryApproval {
                reviewed_by: "Jane Doe".to_string(),
                date: "2026-09-14".to_string(),
                reason: "team needs blame history for a legacy module".to_string(),
            }),
        };
        assert_eq!(resolve(&config), Ok(GitHistoryMode::RealHistoryReadOnly));
    }
}
