//! `habitat-policy` -- schema types and loader for the shared config/policy
//! location.
//!
//! This crate is the single place the secrets blocklist, egress allowlist,
//! resource-limit defaults, and the git-history toggle are defined and
//! read from -- both `habitat-workspace` (blocklist, git-history toggle)
//! and `habitat-egress` (allowlist) depend on it rather than keeping their
//! own copies (`file-structure.md` Section 2).
//!
//! It reads:
//! - the default policy data under `/policy` at the repo root (Phase 2 for
//!   the blocklist, Phase 5 for the allowlist), and
//! - the checked-in operator config file (`habitat run --config ...`,
//!   assembled in Phase 7), which may only *add to* allowlist/blocklist
//!   entries or adjust resource limits/toggles -- never disable
//!   containment, blocklist enforcement, or patch validation (AGENTS.md
//!   Section 2; `docs/plan.md` Section 2.5's "one hardened setup" rule).
//!
//! Phase 1 slice: just the audit-log destination default, needed by
//! `habitat-install` so preflight/install failures have somewhere to log
//! to before the rest of the policy loader exists. Blocklist/allowlist/
//! resource-limit schema and loading land in Phases 2, 5, and 7
//! respectively -- this file intentionally does not get ahead of them.
//!
//! Phase 2 adds: the secrets blocklist ([`blocklist`], defaults plus the
//! per-project extension mechanism), the git-history toggle
//! ([`git_history`], default off, hard-fails closed without a logged
//! approval), and the Phase 2 slice of the checked-in project config
//! ([`config`]) that carries both. The rest of the operator config
//! schema (Phase 7) is still to come.
//!
//! Adds: content-based secrets scanning ([`secrets_scan`], Betterleaks-
//! powered), named alongside the filename blocklist under one
//! `secrets_scan:` config mapping (`filenames` / `content`, both default
//! enabled) rather than a second, parallel config surface -- per
//! `file-structure.md` Section 4's "no second config/policy directory"
//! rule. `crates/workspace` is what actually shells out to the
//! `betterleaks` binary; this crate only owns the schema, the toggle
//! defaults, and the baseline/project ruleset merge rule.
//!
//! Phase 3 adds: [`resource_limits`], the CPU/memory-cap schema
//! `crates/vm`'s launcher reads to bound each session's microVM -- same
//! "shared, not duplicated per-domain" rule, just for a different
//! consumer than the blocklist/allowlist.
//!
//! Phase 5 adds: [`egress_allowlist`], the default-deny egress allowlist
//! schema `crates/egress`'s local proxy checks every guest connection's
//! SNI hostname against -- built-in defaults plus a project's own
//! additive-only `egress_allowlist_additions` (`config::ProjectConfig`),
//! same "shared, not duplicated per-domain" rule as the blocklist.

pub mod blocklist;
pub mod config;
pub mod egress_allowlist;
pub mod git_history;
pub mod resource_limits;
pub mod secrets_scan;

use std::path::PathBuf;

/// Default location for the boundary audit log, absent any `--config`
/// override (Phase 7 wires the override; this is just the built-in
/// default). Resolution order mirrors the XDG base-directory spec:
/// `$XDG_STATE_HOME/habitat/audit.log`, falling back to
/// `$HOME/.local/state/habitat/audit.log`, falling back to a relative path
/// in the current directory if neither environment variable is set (e.g.
/// a minimal/non-interactive shell) -- the fallback still gives every
/// caller *a* writable path rather than failing to resolve one at all.
pub fn default_audit_log_path() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_STATE_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("habitat").join("audit.log");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("habitat")
                .join("audit.log");
        }
    }
    PathBuf::from("habitat-audit.log")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `std::env::set_var`/`remove_var` are process-global, and cargo runs
    // tests for one crate in multiple threads of the same process by
    // default. Serialize the two env-dependent tests below so they can't
    // interleave and read each other's mutated state.
    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn prefers_xdg_state_home_when_set() {
        let _guard = ENV_TEST_LOCK.lock().unwrap();
        std::env::set_var("XDG_STATE_HOME", "/tmp/xdg-state-test");
        let path = default_audit_log_path();
        std::env::remove_var("XDG_STATE_HOME");
        assert_eq!(path, PathBuf::from("/tmp/xdg-state-test/habitat/audit.log"));
    }

    #[test]
    fn falls_back_to_home_when_xdg_state_home_unset() {
        let _guard = ENV_TEST_LOCK.lock().unwrap();
        std::env::remove_var("XDG_STATE_HOME");
        std::env::set_var("HOME", "/tmp/home-test");
        let path = default_audit_log_path();
        std::env::remove_var("HOME");
        assert_eq!(
            path,
            PathBuf::from("/tmp/home-test/.local/state/habitat/audit.log")
        );
    }
}
