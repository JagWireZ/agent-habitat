//! The git-history toggle (Phase 2): synthetic repo by default, real
//! `.git` shared read-only only when a project's checked-in config turns
//! that on -- and turning it on requires a logged, reviewed approval
//! entry to already be present, or resolution is a hard failure, never a
//! silent pass-through (AGENTS.md Section 2 invariant 9, Section 8).
//!
//! This module only resolves *whether* real history is permitted for a
//! given, already-loaded config; `crates/workspace`'s disk-build pipeline
//! is what actually acts on the result (seed a synthetic repo, or copy
//! the real `.git` in read-only).

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

/// The logged, reviewed entry AGENTS.md Section 8 requires before a
/// git-history-toggle flip takes effect. All three fields are required
/// and must be non-empty -- this is the config-level record; the
/// quarterly governance review (`reviews/CHECKLIST.md`) separately
/// confirms each flip like this one actually happened and links back to
/// it, but does not substitute for it being present up front.
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

/// Why real history was refused. There is deliberately no "warning" or
/// "degraded mode" variant -- resolution either produces a mode or it
/// fails closed to [`GitHistoryMode::Synthetic`] being the only option
/// left unresolved, per AGENTS.md Section 2 invariant 10's "distinct
/// state, never silently merged/dropped" standard applied here to
/// ambiguous config, not just sync patches.
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
/// - `enabled: false` (the default) always resolves to `Synthetic`,
///   regardless of whatever an `approval` field might contain -- an
///   approval left over from a previous, later-reverted flip must never
///   cause real history to leak back in on its own.
/// - `enabled: true` requires a complete `approval` (all three fields
///   non-empty) to resolve to `RealHistoryReadOnly`. A missing or
///   incomplete approval is a hard `Err`, never a fallback to
///   `Synthetic` and never a warning-only pass-through -- flipping the
///   toggle on is a deliberate request for more exposure, and an
///   unapproved request must stop the build, not quietly under-deliver
///   it.
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
                      on requires a reviewed entry before it takes effect (AGENTS.md Section 8)"
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
