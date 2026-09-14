//! The checked-in, per-project config file -- Phase 2 slice.
//!
//! `docs/plan.md` Section 2.5 describes one operator-facing config file
//! (resource limits, egress allowlist additions, git-history toggle,
//! audit on/off, blocklist additions), assembled behind `habitat run
//! --config` in Phase 7. Phase 2 only needs two of those fields --
//! blocklist additions and the git-history toggle -- so this module
//! reads just those, in a plain, hand-rolled `key: value` format that is
//! valid YAML (a strict subset of it: no flow style, no multi-line
//! scalars, no anchors). Phase 7 is expected to *extend* this schema
//! (add `resource_limits`, `egress_allowlist_additions`, `audit`) rather
//! than replace the file shape, and may swap this hand-rolled reader for
//! a real YAML parser once the full schema needs one -- files written
//! against this Phase 2 reader stay valid input either way, since the
//! subset accepted here is unambiguous YAML.
//!
//! Loading is intentionally permissive about the file's *absence* (no
//! config file at all is just "use every default") and strict about its
//! *shape* once present: an unrecognized top-level key is a hard load
//! error rather than a silently-ignored typo, since a operator who thinks
//! `git_hstory:` (typo) turned a toggle on deserves a load failure, not
//! quiet non-effect.

use crate::git_history::{GitHistoryApproval, GitHistoryConfig};
use std::fmt;
use std::path::Path;

/// The Phase 2 slice of the checked-in project config. Phase 7 adds
/// fields here; it does not replace this one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectConfig {
    pub blocklist_additions: Vec<String>,
    pub git_history: GitHistoryConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "project config: {}", self.message)
    }
}

impl std::error::Error for ConfigError {}

fn err(message: impl Into<String>) -> ConfigError {
    ConfigError {
        message: message.into(),
    }
}

/// Loads a project's config file from `path`. A missing file resolves to
/// `Ok(ProjectConfig::default())` -- a project need not have this file at
/// all. A present-but-malformed file is `Err`, never a partial/best-effort
/// parse.
pub fn load(path: &Path) -> Result<ProjectConfig, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => parse(&contents),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ProjectConfig::default()),
        Err(e) => Err(err(format!("could not read {}: {e}", path.display()))),
    }
}

/// Parses config file contents already read into memory (split out from
/// [`load`] so tests exercise the parser without touching the
/// filesystem).
pub fn parse(contents: &str) -> Result<ProjectConfig, ConfigError> {
    let lines: Vec<&str> = contents
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .collect();

    let mut config = ProjectConfig::default();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if indent_of(line) != 0 {
            return Err(err(format!(
                "unexpected indentation on line {:?} (not under a recognized top-level key)",
                line.trim()
            )));
        }
        let (key, rest) = split_key(line)?;
        match key {
            "blocklist_additions" => {
                if !rest.trim().is_empty() {
                    return Err(err(
                        "blocklist_additions: must be a list (a bare value isn't allowed)",
                    ));
                }
                let (items, consumed) = parse_list(&lines, i + 1)?;
                config.blocklist_additions = items;
                i += 1 + consumed;
            }
            "git_history" => {
                if !rest.trim().is_empty() {
                    return Err(err(
                        "git_history: must be a mapping (a bare value isn't allowed)",
                    ));
                }
                let (git_history, consumed) = parse_git_history(&lines, i + 1)?;
                config.git_history = git_history;
                i += 1 + consumed;
            }
            other => {
                return Err(err(format!(
                    "unrecognized top-level config key {other:?} -- refusing to guess what it \
                     meant rather than silently ignoring it"
                )));
            }
        }
    }
    Ok(config)
}

/// Indentation (leading space count) of a line, used to tell a nested
/// entry from a top-level key. Tabs are rejected outright (YAML forbids
/// them for indentation; keeping that rule avoids ambiguity here too).
fn indent_of(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

fn split_key(line: &str) -> Result<(&str, &str), ConfigError> {
    match line.split_once(':') {
        Some((k, v)) => Ok((k.trim(), v)),
        None => Err(err(format!(
            "expected 'key: value' on line {line:?} (no ':' found)"
        ))),
    }
}

/// Strips a matching pair of surrounding quotes (`"..."` or `'...'`) from
/// a scalar value, if present; otherwise returns it trimmed as-is. Plain
/// (unquoted) scalars are the common case for these fields.
fn unquote(value: &str) -> String {
    let v = value.trim();
    let bytes = v.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return v[1..v.len() - 1].to_string();
        }
    }
    v.to_string()
}

/// Parses a YAML-style `- item` block list starting at `lines[start]`.
/// Returns the parsed items and how many lines (starting at `start`) were
/// consumed.
fn parse_list(lines: &[&str], start: usize) -> Result<(Vec<String>, usize), ConfigError> {
    let mut items = Vec::new();
    let mut i = start;
    while i < lines.len() && indent_of(lines[i]) > 0 {
        let trimmed = lines[i].trim_start();
        match trimmed
            .strip_prefix("- ")
            .or_else(|| if trimmed == "-" { Some("") } else { None })
        {
            Some(item) => items.push(unquote(item)),
            None => {
                return Err(err(format!(
                    "expected a '- item' list entry, found {:?}",
                    lines[i].trim()
                )))
            }
        }
        i += 1;
    }
    Ok((items, i - start))
}

/// Parses the `git_history:` mapping's nested `enabled` / `approved_by` /
/// `approved_date` / `reason` keys.
fn parse_git_history(
    lines: &[&str],
    start: usize,
) -> Result<(GitHistoryConfig, usize), ConfigError> {
    let mut enabled = false;
    let mut reviewed_by: Option<String> = None;
    let mut date: Option<String> = None;
    let mut reason: Option<String> = None;

    let mut i = start;
    while i < lines.len() && indent_of(lines[i]) > 0 {
        let (key, rest) = split_key(lines[i].trim_start())?;
        let value = unquote(rest);
        match key {
            "enabled" => {
                enabled = parse_bool(&value)?;
            }
            "approved_by" => reviewed_by = Some(value),
            "approved_date" => date = Some(value),
            "reason" => reason = Some(value),
            other => return Err(err(format!("unrecognized key {other:?} under git_history"))),
        }
        i += 1;
    }

    let approval = match (reviewed_by, date, reason) {
        (None, None, None) => None,
        (reviewed_by, date, reason) => Some(GitHistoryApproval {
            reviewed_by: reviewed_by.unwrap_or_default(),
            date: date.unwrap_or_default(),
            reason: reason.unwrap_or_default(),
        }),
    };

    Ok((GitHistoryConfig { enabled, approval }, i - start))
}

fn parse_bool(value: &str) -> Result<bool, ConfigError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(err(format!(
            "expected 'true' or 'false' for a boolean field, got {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_loads_as_default() {
        let config = load(Path::new("/nonexistent/does-not-exist.yaml")).unwrap();
        assert_eq!(config, ProjectConfig::default());
    }

    #[test]
    fn empty_contents_parse_as_default() {
        assert_eq!(parse("").unwrap(), ProjectConfig::default());
        assert_eq!(
            parse("# just a comment\n").unwrap(),
            ProjectConfig::default()
        );
    }

    #[test]
    fn parses_blocklist_additions_list() {
        let config = parse("blocklist_additions:\n  - \"*.mysecret\"\n  - local.creds\n").unwrap();
        assert_eq!(
            config.blocklist_additions,
            vec!["*.mysecret".to_string(), "local.creds".to_string()]
        );
    }

    #[test]
    fn parses_git_history_off_by_default_shape() {
        let config = parse("git_history:\n  enabled: false\n").unwrap();
        assert!(!config.git_history.enabled);
        assert_eq!(config.git_history.approval, None);
    }

    #[test]
    fn parses_git_history_on_with_full_approval() {
        let src = "git_history:\n  enabled: true\n  approved_by: Jane Doe\n  approved_date: 2026-09-14\n  reason: legacy blame needed\n";
        let config = parse(src).unwrap();
        assert!(config.git_history.enabled);
        let approval = config.git_history.approval.unwrap();
        assert_eq!(approval.reviewed_by, "Jane Doe");
        assert_eq!(approval.date, "2026-09-14");
        assert_eq!(approval.reason, "legacy blame needed");
    }

    #[test]
    fn parses_both_sections_together() {
        let src = "blocklist_additions:\n  - internal.secret\ngit_history:\n  enabled: false\n";
        let config = parse(src).unwrap();
        assert_eq!(
            config.blocklist_additions,
            vec!["internal.secret".to_string()]
        );
        assert!(!config.git_history.enabled);
    }

    #[test]
    fn unrecognized_top_level_key_is_a_hard_error() {
        let err = parse("git_hstory:\n  enabled: true\n").unwrap_err();
        assert!(err.message.contains("unrecognized"));
    }

    #[test]
    fn unrecognized_git_history_key_is_a_hard_error() {
        let err = parse("git_history:\n  enalbed: true\n").unwrap_err();
        assert!(err.message.contains("unrecognized"));
    }

    #[test]
    fn malformed_boolean_is_a_hard_error() {
        let err = parse("git_history:\n  enabled: yes\n").unwrap_err();
        assert!(err.message.contains("true"));
    }

    #[test]
    fn malformed_list_entry_is_a_hard_error() {
        let err = parse("blocklist_additions:\n  not_a_list_item\n").unwrap_err();
        assert!(err.message.contains("list entry"));
    }
}
