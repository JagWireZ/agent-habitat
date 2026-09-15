//! The default egress allowlist (Phase 5): sensible built-in defaults
//! plus a per-project extension mechanism, and the matching rule the
//! local proxy (`crates/egress`) checks every SNI hostname against.
//!
//! Same shape as `crate::blocklist` (Phase 2): built-in defaults are
//! baked into the binary via `include_str!`, never re-read from disk at
//! runtime, and a project's own additions from its checked-in config are
//! always additive -- no mechanism here lets a project remove or weaken
//! a default entry (`docs/plan.md` Section 2.5's "one hardened setup"
//! rule, applied here ahead of Phase 7 formally wiring the rest of that
//! config file).
//!
//! Matching is by destination hostname only, never by IP address
//! (`docs/decisions/0004-networking-layer.md`): a connection that names
//! no hostname at all (e.g. a direct-IP TLS ClientHello with no SNI
//! extension, or a malformed one) has nothing here to match against and
//! is denied by construction -- there is no IP-based fallback path.

/// The built-in default patterns (see `policy/egress_allowlist.txt` and
/// `policy/README.md`).
const DEFAULT_ALLOWLIST_SRC: &str = include_str!("../../../policy/egress_allowlist.txt");

/// Parses `policy/egress_allowlist.txt`: one pattern per non-blank,
/// non-comment (`#`) line, surrounding whitespace trimmed, lowercased
/// (hostnames are case-insensitive).
pub fn default_entries() -> Vec<String> {
    parse_pattern_lines(DEFAULT_ALLOWLIST_SRC)
}

fn parse_pattern_lines(src: &str) -> Vec<String> {
    src.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_ascii_lowercase())
        .collect()
}

/// The allowlist actually enforced for a given project: built-in
/// defaults plus that project's own additions from its checked-in config
/// (`crate::config::ProjectConfig::egress_allowlist_additions`).
/// Additive only -- there is no mechanism here for a project to remove or
/// weaken a default entry.
pub fn effective_entries(project_additions: &[String]) -> Vec<String> {
    let mut entries = default_entries();
    entries.extend(
        project_additions
            .iter()
            .map(|s| s.trim().to_ascii_lowercase()),
    );
    entries
}

/// Whether `hostname` (as named by a guest's TLS ClientHello SNI
/// extension) is reachable under `entries`. Case-insensitive; a trailing
/// `.` (a fully-qualified DNS name written with one) is stripped before
/// comparison so `example.com.` and `example.com` match the same entry.
///
/// This is the single implementation the local proxy
/// (`crates/egress::proxy`) calls on every connection -- never
/// re-derived per call site.
pub fn is_allowed(entries: &[String], hostname: &str) -> bool {
    let hostname = normalize(hostname);
    if hostname.is_empty() {
        return false;
    }
    entries.iter().any(|entry| host_matches(&hostname, entry))
}

fn normalize(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A bare entry (`example.com`) matches that exact host only. A
/// `*.`-prefixed entry (`*.example.com`) matches any strict subdomain of
/// the suffix -- `api.example.com` and `deep.api.example.com` both
/// match, but `example.com` itself does not (list it separately if it
/// must also be reachable).
fn host_matches(hostname: &str, entry: &str) -> bool {
    match entry.strip_prefix("*.") {
        Some(suffix) => {
            hostname != suffix && hostname.ends_with(suffix) && {
                // Confirm the match lands on a label boundary, not a bare
                // string-suffix coincidence (`evilexample.com` must not match
                // `*.example.com` just because it ends with "example.com").
                let boundary = hostname.len() - suffix.len();
                boundary > 0 && hostname.as_bytes()[boundary - 1] == b'.'
            }
        }
        None => hostname == entry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_entries_include_a_major_ai_provider_and_a_package_registry() {
        let entries = default_entries();
        assert!(entries.contains(&"api.anthropic.com".to_string()));
        assert!(entries.contains(&"pypi.org".to_string()));
        assert!(entries.contains(&"crates.io".to_string()));
    }

    #[test]
    fn exact_entry_matches_only_that_host() {
        let entries = vec!["pypi.org".to_string()];
        assert!(is_allowed(&entries, "pypi.org"));
        assert!(!is_allowed(&entries, "evil-pypi.org"));
        assert!(!is_allowed(&entries, "sub.pypi.org"));
    }

    #[test]
    fn wildcard_entry_matches_subdomains_but_not_the_bare_suffix() {
        let entries = vec!["*.githubusercontent.com".to_string()];
        assert!(is_allowed(&entries, "objects.githubusercontent.com"));
        assert!(is_allowed(&entries, "raw.githubusercontent.com"));
        assert!(!is_allowed(&entries, "githubusercontent.com"));
    }

    #[test]
    fn wildcard_entry_does_not_match_a_bare_suffix_coincidence() {
        let entries = vec!["*.example.com".to_string()];
        assert!(!is_allowed(&entries, "evilexample.com"));
    }

    #[test]
    fn matching_is_case_insensitive_and_ignores_a_trailing_dot() {
        let entries = vec!["pypi.org".to_string()];
        assert!(is_allowed(&entries, "PyPI.org"));
        assert!(is_allowed(&entries, "pypi.org."));
    }

    #[test]
    fn empty_hostname_is_never_allowed() {
        let entries = default_entries();
        assert!(!is_allowed(&entries, ""));
    }

    #[test]
    fn effective_entries_adds_project_additions_without_dropping_defaults() {
        let entries = effective_entries(&["internal.registry.example".to_string()]);
        assert!(entries.contains(&"pypi.org".to_string()));
        assert!(entries.contains(&"internal.registry.example".to_string()));
    }

    #[test]
    fn a_hostname_absent_from_every_entry_is_denied() {
        let entries = default_entries();
        assert!(!is_allowed(&entries, "attacker.example"));
    }
}
