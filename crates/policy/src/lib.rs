//! `habitat-policy` -- schema types and loader for the shared config/policy
//! location: the secrets blocklist ([`blocklist`]), content-based secrets
//! scanning ([`secrets_scan`]), the git-history toggle ([`git_history`]),
//! resource limits ([`resource_limits`]), the egress allowlist
//! ([`egress_allowlist`]), and the checked-in project config ([`config`])
//! that carries per-project additions to all of the above.
//!
//! `habitat-workspace` and `habitat-egress` depend on this crate rather than
//! keeping their own copies of this schema. Project config may only *add to*
//! allowlist/blocklist entries or adjust resource limits/toggles -- never
//! disable containment, blocklist enforcement, or patch validation.

pub mod blocklist;
pub mod config;
pub mod egress_allowlist;
pub mod git_history;
pub mod resource_limits;
pub mod secrets_scan;

use std::path::PathBuf;

/// Default location for the boundary audit log, absent any `--config`
/// override. Resolution follows the XDG base-directory spec:
/// `$XDG_STATE_HOME/habitat/audit.log`, falling back to
/// `$HOME/.local/state/habitat/audit.log`, falling back to a relative path
/// if neither env var is set, so callers always get *a* writable path.
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

    // env vars are process-global; serialize the env-dependent tests below
    // so parallel test threads can't interleave and clobber each other's state.
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
