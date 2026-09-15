//! Content-based secrets scanning (Betterleaks), alongside the existing
//! filename-based blocklist ([`crate::blocklist`]). Both are named
//! explicitly under one `secrets_scan:` mapping in the checked-in project
//! config (`crate::config`):
//!
//! ```yaml
//! secrets_scan:
//!   filenames: enabled | disabled   # the existing blocklist mechanism
//!   content: enabled | disabled     # Betterleaks-based content scan
//!   content_rules_path: "./custom-betterleaks.toml"   # optional
//! ```
//!
//! Both default to `enabled` -- disabling either is an explicit, visible
//! opt-out a team chooses in its checked-in config, never the
//! out-of-the-box state (`docs/plan.md` Section 2.5's "one hardened
//! setup" rule).
//!
//! This module owns two things: the toggle/config types themselves, and
//! resolving+merging the *content* ruleset actually handed to the
//! `betterleaks` binary (`crates/workspace` is what actually shells out to
//! it -- this module never runs a process). A project's own
//! `betterleaks.toml` is additive to Habitat's bundled baseline rules,
//! never a full replacement -- see [`merge_rules`] for why an empty
//! project ruleset or an overly broad allowlist rule can't be used to
//! fully disable detection.

use std::fmt;
use std::path::{Path, PathBuf};

/// The bundled baseline content-scan ruleset, baked into the binary at
/// compile time (see `policy/betterleaks-baseline.toml`) -- not re-read
/// from disk at runtime, mirroring [`crate::blocklist`]'s
/// `DEFAULT_BLOCKLIST_SRC`: a compromised or edited on-disk copy after
/// install can't change what ships.
const BASELINE_RULES_SRC: &str = include_str!("../../../policy/betterleaks-baseline.toml");

/// An `enabled`/`disabled` toggle. Deliberately not a plain `bool` in the
/// config schema -- `enabled`/`disabled` reads unambiguously in a checked-
/// in YAML file, where `true`/`false` alone doesn't say what's being
/// toggled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toggle {
    Enabled,
    Disabled,
}

impl Toggle {
    pub fn is_enabled(self) -> bool {
        matches!(self, Toggle::Enabled)
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "enabled" => Ok(Toggle::Enabled),
            "disabled" => Ok(Toggle::Disabled),
            other => Err(format!("expected 'enabled' or 'disabled', got {other:?}")),
        }
    }
}

/// Both mechanisms default to enabled -- this is what makes disabling
/// either one an explicit, visible opt-out rather than the shipped state.
impl Default for Toggle {
    fn default() -> Self {
        Toggle::Enabled
    }
}

/// The `secrets_scan:` slice of a project's checked-in config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsScanConfig {
    /// The existing filename blocklist mechanism ([`crate::blocklist`]),
    /// now named explicitly rather than being always-on with no toggle.
    pub filenames: Toggle,
    /// The new Betterleaks-based content scan.
    pub content: Toggle,
    /// Optional override pointing at a custom Betterleaks ruleset. If
    /// unset, resolution falls back to a `betterleaks.toml` in the
    /// mounted project root, then to the bundled baseline alone -- see
    /// [`resolve_project_rules_path`].
    pub content_rules_path: Option<String>,
}

impl Default for SecretsScanConfig {
    fn default() -> Self {
        SecretsScanConfig {
            filenames: Toggle::Enabled,
            content: Toggle::Enabled,
            content_rules_path: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentRulesError {
    pub message: String,
}

impl fmt::Display for ContentRulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "content-scan ruleset: {}", self.message)
    }
}

impl std::error::Error for ContentRulesError {}

fn err(message: impl Into<String>) -> ContentRulesError {
    ContentRulesError {
        message: message.into(),
    }
}

/// The bundled baseline ruleset text -- always the starting point of
/// [`merge_rules`], regardless of what a project supplies.
pub fn baseline_rules() -> &'static str {
    BASELINE_RULES_SRC
}

/// Resolves which on-disk path (if any) holds the project's own additive
/// ruleset, per the documented order:
///
/// 1. `configured` (the config file's `content_rules_path`, if set) --
///    resolved relative to `project_root` when it isn't already absolute.
/// 2. A `betterleaks.toml` found at `project_root`, if one exists.
/// 3. Neither -- `None`, meaning the bundled baseline alone applies.
///
/// This only resolves a *path*; it never reads file contents (see
/// [`load_effective_ruleset`] for that).
pub fn resolve_project_rules_path(
    project_root: &Path,
    configured: Option<&str>,
) -> Option<PathBuf> {
    if let Some(configured) = configured {
        let p = Path::new(configured);
        return Some(if p.is_absolute() {
            p.to_path_buf()
        } else {
            project_root.join(p)
        });
    }
    let default_path = project_root.join("betterleaks.toml");
    if default_path.is_file() {
        Some(default_path)
    } else {
        None
    }
}

/// Resolves and reads the project's own ruleset (if any), then merges it
/// with the bundled baseline via [`merge_rules`]. This is the one function
/// that touches the filesystem in this module -- callers that already
/// have file contents in hand (e.g. a snapshot taken once at session
/// start, see the module-level note in `crates/workspace`) should call
/// [`merge_rules`] directly instead of re-reading here.
pub fn load_effective_ruleset(
    project_root: &Path,
    configured_path: Option<&str>,
) -> Result<String, ContentRulesError> {
    let project_src = match resolve_project_rules_path(project_root, configured_path) {
        Some(path) => Some(std::fs::read_to_string(&path).map_err(|e| {
            err(format!(
                "could not read project ruleset {}: {e}",
                path.display()
            ))
        })?),
        None => None,
    };
    merge_rules(baseline_rules(), project_src.as_deref())
}

/// Merges `baseline` (always included, always first) with an optional
/// project-supplied ruleset (`project`), producing the effective ruleset
/// text handed to the `betterleaks` binary.
///
/// The baseline is unconditionally present in the result regardless of
/// what `project` contains -- an empty or missing project ruleset can
/// therefore never weaken detection below the baseline, by construction.
/// The one thing a project ruleset genuinely could do to weaken detection
/// -- add an allowlist rule broad enough to suppress findings wholesale
/// -- is explicitly rejected by [`rejects_if_disables_baseline`] before
/// being appended.
pub fn merge_rules(baseline: &str, project: Option<&str>) -> Result<String, ContentRulesError> {
    if let Some(project) = project {
        reject_if_disables_baseline(project)?;
    }
    let mut effective = String::new();
    effective.push_str(
        "# Baseline rules (Agent Habitat) -- always enforced, never removable by project config.\n",
    );
    effective.push_str(baseline);
    if let Some(project) = project {
        effective.push_str(
            "\n# Project-supplied additive rules (betterleaks.toml) -- appended to, never replacing, the baseline above.\n",
        );
        effective.push_str(project);
    }
    Ok(effective)
}

/// A project ruleset with no `[allowlist]`/`[[allowlist]]` section at all
/// is trivially fine -- it can only ever add rules, not suppress them. An
/// empty ruleset (no content at all) is likewise fine for the same
/// reason: [`merge_rules`] never omits the baseline.
///
/// What is rejected: an allowlist entry whose `regexes`/`regex`/`paths`
/// value is a catch-all pattern (`.*`, `.+`, `^.*$`, `^.+$`) that would
/// suppress every finding, from the baseline included, rather than
/// excluding a specific known-safe case. This is a deliberately narrow,
/// hand-rolled heuristic (no TOML-parsing dependency is available in this
/// workspace, matching `blocklist.rs`'s and `config.rs`'s own hand-rolled
/// parsers) -- it is not a full TOML validator, just a guard against the
/// specific "disable detection via the allowlist" attack this module's
/// contract explicitly rules out.
fn reject_if_disables_baseline(project_src: &str) -> Result<(), ContentRulesError> {
    const CATCH_ALL_PATTERNS: [&str; 4] = [".*", ".+", "^.*$", "^.+$"];
    let mut in_allowlist = false;
    for raw_line in project_src.lines() {
        let line = raw_line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            let header = line.trim_start_matches('[').trim_end_matches(']');
            in_allowlist = header.eq_ignore_ascii_case("allowlist")
                || header.to_ascii_lowercase().starts_with("allowlist");
            continue;
        }
        if !in_allowlist {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key != "regexes" && key != "regex" && key != "paths" {
            continue;
        }
        for pattern in CATCH_ALL_PATTERNS {
            if value.contains(&format!("\"{pattern}\"")) {
                return Err(err(format!(
                    "project betterleaks.toml's [allowlist] contains a catch-all pattern \
                     ({pattern:?} in {key}) that would suppress every finding, including the \
                     baseline's -- refusing to load a ruleset that could fully disable detection"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_defaults_to_enabled() {
        assert_eq!(Toggle::default(), Toggle::Enabled);
        assert!(Toggle::default().is_enabled());
    }

    #[test]
    fn toggle_parses_enabled_and_disabled_only() {
        assert_eq!(Toggle::parse("enabled"), Ok(Toggle::Enabled));
        assert_eq!(Toggle::parse("disabled"), Ok(Toggle::Disabled));
        assert!(Toggle::parse("yes").is_err());
    }

    #[test]
    fn secrets_scan_config_defaults_both_toggles_enabled() {
        let config = SecretsScanConfig::default();
        assert!(config.filenames.is_enabled());
        assert!(config.content.is_enabled());
        assert_eq!(config.content_rules_path, None);
    }

    #[test]
    fn resolve_project_rules_path_prefers_configured_override() {
        let dir = std::env::temp_dir().join(format!(
            "habitat-policy-secrets-scan-test-configured-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("betterleaks.toml"), "# project default").unwrap();
        std::fs::write(dir.join("custom.toml"), "# custom").unwrap();

        let resolved = resolve_project_rules_path(&dir, Some("custom.toml")).unwrap();
        assert_eq!(resolved, dir.join("custom.toml"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_project_rules_path_falls_back_to_project_root_betterleaks_toml() {
        let dir = std::env::temp_dir().join(format!(
            "habitat-policy-secrets-scan-test-fallback-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("betterleaks.toml"), "# project default").unwrap();

        let resolved = resolve_project_rules_path(&dir, None).unwrap();
        assert_eq!(resolved, dir.join("betterleaks.toml"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_project_rules_path_is_none_when_nothing_present() {
        let dir = std::env::temp_dir().join(format!(
            "habitat-policy-secrets-scan-test-none-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(resolve_project_rules_path(&dir, None), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn merge_rules_always_includes_baseline_even_with_no_project_ruleset() {
        let merged = merge_rules("baseline-rule-marker", None).unwrap();
        assert!(merged.contains("baseline-rule-marker"));
    }

    #[test]
    fn merge_rules_is_additive_with_a_well_formed_project_ruleset() {
        let merged = merge_rules(
            "baseline-rule-marker",
            Some("[[rules]]\nid = \"project-custom-rule\"\n"),
        )
        .unwrap();
        assert!(merged.contains("baseline-rule-marker"));
        assert!(merged.contains("project-custom-rule"));
    }

    #[test]
    fn merge_rules_rejects_an_empty_project_ruleset_gracefully_not_by_dropping_baseline() {
        // An empty project ruleset isn't an error -- it's a no-op addition
        // -- but the baseline must still be present either way.
        let merged = merge_rules("baseline-rule-marker", Some("")).unwrap();
        assert!(merged.contains("baseline-rule-marker"));
    }

    #[test]
    fn merge_rules_rejects_a_catch_all_allowlist_regex() {
        let project = "[allowlist]\nregexes = [\".*\"]\n";
        let err = merge_rules("baseline-rule-marker", Some(project)).unwrap_err();
        assert!(err.message.contains("catch-all"));
    }

    #[test]
    fn merge_rules_rejects_a_catch_all_allowlist_path() {
        let project = "[[allowlist]]\npaths = [\".+\"]\n";
        let err = merge_rules("baseline-rule-marker", Some(project)).unwrap_err();
        assert!(err.message.contains("catch-all"));
    }

    #[test]
    fn merge_rules_allows_a_narrow_allowlist_entry() {
        let project = "[allowlist]\npaths = [\"testdata/fixtures/.*\\\\.pem\"]\n";
        let merged = merge_rules("baseline-rule-marker", Some(project)).unwrap();
        assert!(merged.contains("baseline-rule-marker"));
        assert!(merged.contains("testdata/fixtures"));
    }

    #[test]
    fn load_effective_ruleset_merges_baseline_with_the_resolved_project_file() {
        let dir = std::env::temp_dir().join(format!(
            "habitat-policy-secrets-scan-test-load-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("betterleaks.toml"),
            "[[rules]]\nid = \"project-custom-rule\"\n",
        )
        .unwrap();

        let effective = load_effective_ruleset(&dir, None).unwrap();
        assert!(effective.contains("project-custom-rule"));
        // Baseline content always present too -- spot-check a pattern that
        // ships in `policy/betterleaks-baseline.toml`.
        assert!(effective.contains("id = \"generic-api-key\""));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
