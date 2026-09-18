//! Content-based secrets scanning (Betterleaks): shells out to the
//! `betterleaks` binary against one file at a time, at the same
//! enforcement point the filename blocklist already uses. `crate::staging`
//! calls [`scan_file`] for every file that survived the filename filter;
//! a finding or a scanner error both route through the same "skip, don't
//! copy" decision -- no "warn only" outcome (AGENTS.md Section 4).
//!
//! **Betterleaks CLI contract assumed here** (no public spec bundled with
//! this repo):
//! - `betterleaks scan --config <ruleset.toml> --format json --file <path>`
//!   scans exactly one file.
//! - Exit code `0`: no findings.
//! - Exit code `1`: findings present, reported as a JSON array of
//!   objects on stdout, each carrying at least a `"rule_id"` string
//!   field.
//! - Any other exit code, or an exit code `1` whose stdout doesn't parse
//!   as that shape, is a scanner error -- fails closed (see [`ScanOutcome`]).

use crate::command_runner::CommandRunner;
use std::fmt;
use std::path::Path;

/// The result of scanning one file's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    /// No findings; safe to copy.
    Clean,
    /// A finding, or a scanner error -- either way, this file must not be
    /// copied. `reason` can embed scanner stderr; treat as
    /// attacker-influenced, never interpolate into a shell.
    Blocked(String),
}

impl ScanOutcome {
    pub fn is_blocked(&self) -> bool {
        matches!(self, ScanOutcome::Blocked(_))
    }
}

/// Scans `path`'s contents against the resolved effective ruleset at
/// `ruleset_path`. Never mutates `path`, only reads it via the
/// `betterleaks` process.
pub fn scan_file(runner: &dyn CommandRunner, path: &Path, ruleset_path: &Path) -> ScanOutcome {
    let Some(path_str) = path.to_str() else {
        return ScanOutcome::Blocked(
            "path is not valid UTF-8 -- cannot safely pass to the content scanner, failing closed"
                .to_string(),
        );
    };
    let Some(ruleset_str) = ruleset_path.to_str() else {
        return ScanOutcome::Blocked(
            "ruleset path is not valid UTF-8 -- failing closed".to_string(),
        );
    };

    let output = match runner.run(
        "betterleaks",
        &[
            "scan",
            "--config",
            ruleset_str,
            "--format",
            "json",
            "--file",
            path_str,
        ],
    ) {
        Ok(output) => output,
        Err(e) => {
            return ScanOutcome::Blocked(format!(
                "could not run betterleaks ({e}) -- failing closed rather than letting an \
                 unscanned file through"
            ))
        }
    };

    match output.status.code() {
        Some(0) => ScanOutcome::Clean,
        Some(1) => match parse_findings(&output.stdout) {
            Ok(findings) if !findings.is_empty() => ScanOutcome::Blocked(format!(
                "content scan found {} potential secret(s): {}",
                findings.len(),
                findings.join(", ")
            )),
            Ok(_) => ScanOutcome::Blocked(
                "betterleaks exited with its findings-present status code but reported no \
                 findings -- ambiguous scanner output, failing closed"
                    .to_string(),
            ),
            Err(e) => ScanOutcome::Blocked(format!(
                "could not parse betterleaks output ({e}) -- failing closed"
            )),
        },
        other => ScanOutcome::Blocked(format!(
            "betterleaks exited with an unexpected status ({other:?}): {} -- failing closed",
            String::from_utf8_lossy(&output.stderr)
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parses betterleaks' JSON findings array, extracting each finding's
/// `"rule_id"` field. Hand-rolled rather than a `serde_json` dependency
/// (no dependency-fetch access in this workspace) -- only needs to
/// handle a flat JSON array of objects with string-valued fields.
fn parse_findings(stdout: &[u8]) -> Result<Vec<String>, ParseError> {
    let text = std::str::from_utf8(stdout).map_err(|e| ParseError {
        message: format!("betterleaks output was not valid UTF-8: {e}"),
    })?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(ParseError {
            message: "betterleaks produced no output to parse".to_string(),
        });
    }
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(ParseError {
            message: "expected a JSON array of findings".to_string(),
        });
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let objects = split_top_level_objects(inner)?;
    let mut rule_ids = Vec::with_capacity(objects.len());
    for obj in objects {
        let rule_id = extract_string_field(&obj, "rule_id").ok_or_else(|| ParseError {
            message: "a finding object is missing a \"rule_id\" field".to_string(),
        })?;
        rule_ids.push(rule_id);
    }
    Ok(rule_ids)
}

/// Splits the inside of a top-level JSON array (already stripped of its
/// surrounding `[`/`]`) into its individual `{...}` object substrings,
/// respecting string quoting and nested braces so a `}` or `,` inside a
/// quoted value never ends an object early.
fn split_top_level_objects(inner: &str) -> Result<Vec<String>, ParseError> {
    let mut objects = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    let mut current = String::new();

    for c in inner.chars() {
        if in_string {
            current.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                current.push(c);
            }
            '{' => {
                depth += 1;
                current.push(c);
            }
            '}' => {
                if depth == 0 {
                    return Err(ParseError {
                        message: "unbalanced '}' in betterleaks output".to_string(),
                    });
                }
                depth -= 1;
                current.push(c);
                if depth == 0 {
                    objects.push(std::mem::take(&mut current));
                }
            }
            ',' if depth == 0 => {}
            c if c.is_whitespace() && depth == 0 => {}
            _ => {
                if depth == 0 {
                    return Err(ParseError {
                        message: "unexpected content outside of a finding object".to_string(),
                    });
                }
                current.push(c);
            }
        }
    }
    if depth != 0 {
        return Err(ParseError {
            message: "unbalanced '{' in betterleaks output".to_string(),
        });
    }
    Ok(objects)
}

/// Extracts a top-level `"key": "value"` string field's value from one
/// JSON object substring. Not a general JSON accessor -- only handles a
/// plain, non-nested string value, which is all this module's contract
/// needs from a finding object.
fn extract_string_field(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let key_pos = obj.find(&needle)?;
    let after_key = &obj[key_pos + needle.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    let mut chars = after_colon.strip_prefix('"')?.chars();
    let mut value = String::new();
    let mut escape = false;
    for c in chars.by_ref() {
        if escape {
            value.push(c);
            escape = false;
            continue;
        }
        match c {
            '\\' => escape = true,
            '"' => return Some(value),
            other => value.push(other),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::testing::FakeCommandRunner;
    use std::path::PathBuf;

    fn temp_file(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "habitat-workspace-content-scan-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn clean_exit_code_zero_is_clean() {
        let path = temp_file("clean", "nothing secret here");
        let ruleset = PathBuf::from("/effective/betterleaks.toml");
        let invocation = format!(
            "betterleaks scan --config {} --format json --file {}",
            ruleset.display(),
            path.display()
        );
        let runner = FakeCommandRunner::default().with_ok(&invocation, "");
        assert_eq!(scan_file(&runner, &path, &ruleset), ScanOutcome::Clean);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn findings_on_exit_code_one_are_blocked_with_rule_ids_named() {
        let path = temp_file("finding", "AKIAABCDEFGHIJKLMNOP");
        let ruleset = PathBuf::from("/effective/betterleaks.toml");
        let invocation = format!(
            "betterleaks scan --config {} --format json --file {}",
            ruleset.display(),
            path.display()
        );
        let runner = FakeCommandRunner::default()
            .with_findings(&invocation, r#"[{"rule_id":"aws-access-key-id","line":1}]"#);
        let outcome = scan_file(&runner, &path, &ruleset);
        match outcome {
            ScanOutcome::Blocked(reason) => assert!(reason.contains("aws-access-key-id")),
            other => panic!("expected Blocked, got {other:?}"),
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn scanner_process_error_fails_closed() {
        let path = temp_file("missing-binary", "irrelevant");
        let ruleset = PathBuf::from("/effective/betterleaks.toml");
        // No invocation configured on the fake -> NotFound, simulating the
        // binary being missing at scan time.
        let runner = FakeCommandRunner::default();
        assert!(scan_file(&runner, &path, &ruleset).is_blocked());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn unparseable_output_on_exit_code_one_fails_closed() {
        let path = temp_file("garbled", "irrelevant");
        let ruleset = PathBuf::from("/effective/betterleaks.toml");
        let invocation = format!(
            "betterleaks scan --config {} --format json --file {}",
            ruleset.display(),
            path.display()
        );
        let runner = FakeCommandRunner::default().with_findings(&invocation, "not json at all");
        assert!(scan_file(&runner, &path, &ruleset).is_blocked());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn empty_findings_array_on_exit_code_one_is_ambiguous_and_fails_closed() {
        let path = temp_file("ambiguous", "irrelevant");
        let ruleset = PathBuf::from("/effective/betterleaks.toml");
        let invocation = format!(
            "betterleaks scan --config {} --format json --file {}",
            ruleset.display(),
            path.display()
        );
        let runner = FakeCommandRunner::default().with_findings(&invocation, "[]");
        assert!(scan_file(&runner, &path, &ruleset).is_blocked());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn unexpected_exit_code_fails_closed() {
        let path = temp_file("weird-exit", "irrelevant");
        let ruleset = PathBuf::from("/effective/betterleaks.toml");
        let invocation = format!(
            "betterleaks scan --config {} --format json --file {}",
            ruleset.display(),
            path.display()
        );
        let runner = FakeCommandRunner::default().with_failure(&invocation, "internal error");
        assert!(scan_file(&runner, &path, &ruleset).is_blocked());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn parse_findings_handles_multiple_objects_and_string_escapes() {
        let stdout = br#"[{"rule_id":"a\"b","file":"x"}, {"rule_id":"c,d"}]"#;
        let findings = parse_findings(stdout).unwrap();
        assert_eq!(findings, vec!["a\"b".to_string(), "c,d".to_string()]);
    }
}
