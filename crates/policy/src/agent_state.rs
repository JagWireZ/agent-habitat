//! The agent state manifest: which agent auth/config files may cross the
//! host/sandbox boundary, and in which direction.
//!
//! This is the "guard's rulebook" side of agent credentials
//! (`AGENTS.md` Section 1): the mechanism that actually copies files lives
//! in `habitat_workspace::agent_state`, but *what* it is allowed to copy is
//! data, defined once here and reviewed like the secrets blocklist.
//!
//! Baked into the binary at compile time (see `policy/agent_state.txt`),
//! not re-read from disk at runtime, and never extensible from a project's
//! checked-in config file -- there is deliberately no "additions" hook.
//! See `docs/decisions/0011-agent-state-copy-in-out.md`.

/// Baked into the binary at compile time -- an edited on-disk copy after
/// install cannot change what ships.
const MANIFEST_SRC: &str = include_str!("../../../policy/agent_state.txt");

/// Which way a file is allowed to move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Credentials/tokens: host -> guest at launch, guest -> host during
    /// and at the end of the session (refresh tokens rotate in-session).
    Auth,
    /// Behavior-affecting configuration: host -> guest at launch only.
    /// Never copied back out.
    Config,
}

/// Whether an entry names one file or a directory tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
}

/// One allowlisted path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `claude`, `codex`, or `opencode`.
    pub agent: String,
    pub role: Role,
    pub kind: Kind,
    /// Relative to the guest's `$HOME`, and to
    /// `~/.habitat/agents/<agent>/` on the host. Always validated by
    /// [`validate_rel_path`].
    pub rel_path: String,
}

/// A manifest line (or the whole manifest) that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "agent state manifest line {}: {}",
            self.line, self.message
        )
    }
}

impl std::error::Error for ManifestError {}

/// Checks a manifest path: relative, only `[A-Za-z0-9._/-]`, no `..`, no
/// empty or `.` components. The manifest is baked in, so this guards
/// against a typo in `policy/agent_state.txt` rather than against an
/// attacker -- but copy-out writes to the host filesystem under this path,
/// so it is checked at parse time and again by the mechanism.
pub fn validate_rel_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("empty path".to_string());
    }
    if !path.is_ascii() {
        return Err(format!("{path:?} contains non-ASCII characters"));
    }
    if path.starts_with('/') {
        return Err(format!("{path:?} must be relative, not absolute"));
    }
    if path.contains('\\') {
        return Err(format!("{path:?} contains a backslash"));
    }
    // Paths end up in `scp` targets and `mkdir`/`head`/`chmod` arguments
    // on the guest, so only a conservative character set is allowed --
    // nothing a shell or the legacy scp protocol could treat specially.
    if !path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
    {
        return Err(format!(
            "{path:?} contains characters outside [A-Za-z0-9._/-]"
        ));
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(format!("{path:?} has an empty, `.`, or `..` component"));
        }
    }
    Ok(())
}

/// Parses manifest text. Strict: an unknown role/kind, a wrong field
/// count, a bad path, an `auth` directory, or a duplicate path is a hard
/// error, never silently skipped.
pub fn parse(src: &str) -> Result<Vec<Entry>, ManifestError> {
    let mut entries: Vec<Entry> = Vec::new();
    for (idx, raw) in src.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 4 {
            return Err(ManifestError {
                line: line_no,
                message: format!(
                    "expected 4 fields (agent role kind path), got {}",
                    fields.len()
                ),
            });
        }
        let role = match fields[1] {
            "auth" => Role::Auth,
            "config" => Role::Config,
            other => {
                return Err(ManifestError {
                    line: line_no,
                    message: format!("unknown role {other:?} (expected auth or config)"),
                })
            }
        };
        let kind = match fields[2] {
            "file" => Kind::File,
            "dir" => Kind::Dir,
            other => {
                return Err(ManifestError {
                    line: line_no,
                    message: format!("unknown kind {other:?} (expected file or dir)"),
                })
            }
        };
        if role == Role::Auth && kind == Kind::Dir {
            return Err(ManifestError {
                line: line_no,
                message: "an auth entry must be a file: copy-out never walks a directory tree"
                    .to_string(),
            });
        }
        validate_rel_path(fields[3]).map_err(|message| ManifestError {
            line: line_no,
            message,
        })?;
        let entry = Entry {
            agent: fields[0].to_string(),
            role,
            kind,
            rel_path: fields[3].to_string(),
        };
        if entries
            .iter()
            .any(|e| e.agent == entry.agent && e.rel_path == entry.rel_path)
        {
            return Err(ManifestError {
                line: line_no,
                message: format!("duplicate entry for {} {}", entry.agent, entry.rel_path),
            });
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// The built-in manifest. A parse failure here is a bug in the baked-in
/// data, caught by this module's tests at build time, so it panics
/// rather than returning a half-trusted list.
pub fn default_entries() -> Vec<Entry> {
    parse(MANIFEST_SRC).expect("policy/agent_state.txt must parse (checked by unit tests)")
}

/// Every agent id that has at least one entry, in first-seen order.
pub fn known_agents() -> Vec<String> {
    let mut agents: Vec<String> = Vec::new();
    for e in default_entries() {
        if !agents.contains(&e.agent) {
            agents.push(e.agent);
        }
    }
    agents
}

/// The entries for exactly the named agents, in manifest order. An agent
/// id with no entries contributes nothing (never an error).
pub fn entries_for(agents: &[&str]) -> Vec<Entry> {
    default_entries()
        .into_iter()
        .filter(|e| agents.contains(&e.agent.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_baked_in_manifest_parses() {
        let entries = parse(MANIFEST_SRC).unwrap();
        assert!(!entries.is_empty());
    }

    #[test]
    fn the_manifest_covers_exactly_the_three_known_agents() {
        assert_eq!(known_agents(), vec!["claude", "codex", "opencode"]);
    }

    #[test]
    fn every_agent_has_at_least_one_auth_file() {
        for agent in known_agents() {
            assert!(
                entries_for(&[&agent])
                    .iter()
                    .any(|e| e.role == Role::Auth && e.kind == Kind::File),
                "{agent} has no auth file entry"
            );
        }
    }

    #[test]
    fn auth_entries_are_always_files() {
        for e in default_entries() {
            if e.role == Role::Auth {
                assert_eq!(e.kind, Kind::File, "{} {}", e.agent, e.rel_path);
            }
        }
    }

    #[test]
    fn manifest_never_lists_transcripts_history_logs_or_databases() {
        // The things `policy/agent_state.txt` documents as deliberately
        // excluded must stay excluded. Matched on path components.
        let forbidden = [
            "projects",
            "sessions",
            "history.jsonl",
            "log",
            "logs",
            "storage",
            "todos",
            "shell-snapshots",
            "plugins_cache",
        ];
        for e in default_entries() {
            for component in e.rel_path.split('/') {
                assert!(
                    !forbidden.contains(&component),
                    "{} {} lists excluded component {component:?}",
                    e.agent,
                    e.rel_path
                );
                assert!(
                    !component.ends_with(".db")
                        && !component.ends_with(".db-wal")
                        && !component.ends_with(".db-shm")
                        && !component.ends_with(".sqlite"),
                    "{} {} looks like a database",
                    e.agent,
                    e.rel_path
                );
            }
        }
    }

    #[test]
    fn no_duplicate_paths_within_an_agent() {
        let entries = default_entries();
        for (i, a) in entries.iter().enumerate() {
            for b in &entries[i + 1..] {
                assert!(
                    !(a.agent == b.agent && a.rel_path == b.rel_path),
                    "duplicate {} {}",
                    a.agent,
                    a.rel_path
                );
            }
        }
    }

    #[test]
    fn entries_for_returns_only_the_named_agents() {
        let only_codex = entries_for(&["codex"]);
        assert!(!only_codex.is_empty());
        assert!(only_codex.iter().all(|e| e.agent == "codex"));
        assert!(entries_for(&["no-such-agent"]).is_empty());
    }

    #[test]
    fn rel_path_validation_rejects_unsafe_paths() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "a/./b",
            "a\\b",
            ".claude/ x",
            "caf\u{e9}/x",
            "a/",
            "a;b",
            "a$b",
            "a*b",
            "a'b",
            "a\nb",
        ] {
            assert!(
                validate_rel_path(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(validate_rel_path(".claude/.credentials.json").is_ok());
        assert!(validate_rel_path(".local/share/opencode/auth.json").is_ok());
    }

    #[test]
    fn parser_is_strict() {
        assert!(parse("claude auth file").is_err());
        assert!(parse("claude secret file .x").is_err());
        assert!(parse("claude auth blob .x").is_err());
        assert!(parse("claude auth dir .x").is_err());
        assert!(parse("claude config file ../x").is_err());
        assert!(parse("claude config file .x\nclaude config dir .x").is_err());
        assert!(parse("# only a comment\n\n").unwrap().is_empty());
    }
}
