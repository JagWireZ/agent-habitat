//! The secrets blocklist: built-in defaults plus a per-project extension
//! mechanism, and the matching rule both are checked against.
//!
//! Deliberately separate from `.gitignore`: `.gitignore` answers "what
//! shouldn't be committed", this answers "what must never reach the
//! sandbox at all", and the two lists diverge in practice.

/// Baked into the binary at compile time (see `policy/blocklist.txt`), not
/// re-read from disk at runtime -- an edited on-disk copy after install
/// can't change what ships.
const DEFAULT_BLOCKLIST_SRC: &str = include_str!("../../../policy/blocklist.txt");

/// Parses `policy/blocklist.txt`: one pattern per non-blank, non-comment
/// (`#`) line, surrounding whitespace trimmed.
pub fn default_patterns() -> Vec<String> {
    parse_pattern_lines(DEFAULT_BLOCKLIST_SRC)
}

fn parse_pattern_lines(src: &str) -> Vec<String> {
    src.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// The blocklist actually enforced for a project: built-in defaults plus
/// that project's own additions. Additive only -- no mechanism here lets a
/// project remove or weaken a default entry.
pub fn effective_patterns(project_additions: &[String]) -> Vec<String> {
    let mut patterns = default_patterns();
    patterns.extend(project_additions.iter().cloned());
    patterns
}

/// Whether `relative_path` (project-relative, `/`-separated regardless of
/// host path conventions, never absolute) matches any blocklist pattern.
pub fn is_blocked(patterns: &[String], relative_path: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| path_matches(relative_path, pattern))
}

/// A pattern with no `/` matches the path's basename, anywhere in the
/// tree (e.g. `*.pem` matches both `x.pem` and `secrets/nested/x.pem`).
/// A pattern with N `/`-separated components matches the path's last N
/// components, each glob-matched against the pattern's corresponding
/// component (e.g. `.aws/credentials` matches `.aws/credentials` and
/// `home/.aws/credentials`, but not `credentials` alone or
/// `other/credentials`).
fn path_matches(relative_path: &str, pattern: &str) -> bool {
    let path_parts: Vec<&str> = relative_path.split('/').collect();
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    if pattern_parts.len() > path_parts.len() {
        return false;
    }
    let start = path_parts.len() - pattern_parts.len();
    path_parts[start..]
        .iter()
        .zip(pattern_parts.iter())
        .all(|(part, pat)| glob_match(part, pat))
}

/// Minimal glob match: `*` matches any run of characters (including none);
/// no other wildcard, no character classes, no `?`. Hand-rolled rather than
/// pulling in a glob crate -- this is security-enforcement logic where a
/// small, fully-inspectable implementation beats a dependency's generality.
fn glob_match(text: &str, pattern: &str) -> bool {
    let t = text.as_bytes();
    let p = pattern.as_bytes();
    let (mut ti, mut pi) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_match_from = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            star_match_from = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            ti += 1;
            pi += 1;
        } else if let Some(star_pi) = star {
            pi = star_pi + 1;
            star_match_from += 1;
            ti = star_match_from;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_patterns_include_the_documented_examples() {
        let patterns = default_patterns();
        for expected in [".env", "*.pem", "*.key", "id_rsa*"] {
            assert!(
                patterns.iter().any(|p| p == expected),
                "expected default pattern {expected:?} to be present, got {patterns:?}"
            );
        }
    }

    #[test]
    fn default_patterns_ignore_blank_lines_and_comments() {
        let parsed = parse_pattern_lines("# comment\n\n  .env  \n\n*.pem\n");
        assert_eq!(parsed, vec![".env".to_string(), "*.pem".to_string()]);
    }

    #[test]
    fn glob_match_handles_prefix_suffix_and_multiple_stars() {
        assert!(glob_match(".env", ".env"));
        assert!(!glob_match(".env.local", ".env"));
        assert!(glob_match("foo.pem", "*.pem"));
        assert!(!glob_match("foo.pem.bak", "*.pem"));
        assert!(glob_match("id_rsa", "id_rsa*"));
        assert!(glob_match("id_rsa.pub", "id_rsa*"));
        assert!(glob_match("id_rsa_backup_key", "id_rsa*key"));
        assert!(!glob_match("id_rsa_backup_key", "id_rsa*.key"));
        assert!(glob_match("id_rsa_backup.key", "id_rsa*.key"));
        assert!(glob_match("anything", "*"));
    }

    #[test]
    fn no_slash_pattern_matches_basename_at_any_depth() {
        assert!(is_blocked(&["*.pem".to_string()], "foo.pem"));
        assert!(is_blocked(&["*.pem".to_string()], "secrets/nested/foo.pem"));
        assert!(!is_blocked(&["*.pem".to_string()], "foo.pem.txt"));
    }

    #[test]
    fn slash_pattern_matches_trailing_components_only() {
        let patterns = vec![".aws/credentials".to_string()];
        assert!(is_blocked(&patterns, ".aws/credentials"));
        assert!(is_blocked(&patterns, "home/.aws/credentials"));
        assert!(!is_blocked(&patterns, "credentials"));
        assert!(!is_blocked(&patterns, "other/credentials"));
        assert!(!is_blocked(&patterns, ".aws/config"));
    }

    #[test]
    fn project_additions_extend_but_never_replace_defaults() {
        let effective = effective_patterns(&["*.mysecret".to_string()]);
        assert!(effective.iter().any(|p| p == ".env"), "defaults retained");
        assert!(
            effective.iter().any(|p| p == "*.mysecret"),
            "addition present"
        );
        assert!(is_blocked(&effective, "notes.mysecret"));
        assert!(is_blocked(&effective, ".env"));
    }

    #[test]
    fn matching_never_consults_gitignore_semantics() {
        // Executable assertion of the blocklist/.gitignore separation, so a
        // future change threading gitignore state in here breaks a visible
        // test, not just a comment.
        let patterns = effective_patterns(&[]);
        assert!(!is_blocked(&patterns, "src/main.rs"));
        assert!(is_blocked(&patterns, ".env"));
    }
}
