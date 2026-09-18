//! `habitat-audit` -- the unified audit log for everything crossing the
//! host/sandbox boundary. Boundary-only; in-sandbox activity is out of scope.
//!
//! Log content is attacker-influenced (e.g. command stderr), so every string
//! is JSON-escaped by hand before it touches disk -- no `serde_json` dep,
//! and nothing here is ever passed through a shell.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The kind of event being recorded. Each variant has a distinct, stable
/// tag string (`EventKind::tag`) so event types are never collapsed into one
/// generic "event" bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// `habitat run`'s preflight subroutine refused to proceed.
    PreflightFailure,
    /// `habitat install` refused to proceed.
    InstallFailure,
    /// `habitat install`'s optional auto-install step ran (or tried to run)
    /// a privileged package-manager command. Logged for every attempt, not
    /// just failures -- running `sudo` on the operator's behalf is
    /// security-relevant regardless of outcome.
    InstallAction,
    /// A sync patch touched a project's `betterleaks.toml` mid-session.
    /// That file governs secrets scanning, and the session's ruleset is a
    /// snapshot taken once at start (never re-read on later sync), so an
    /// edit here must be distinguishable from any other file's edit rather
    /// than silently merged into a stale snapshot. Always emitted alongside
    /// (never instead of) `SyncApplied`/`SyncFlagged` for the same patch --
    /// see `docs/decisions/0007-content-secrets-scan-snapshot.md`.
    ContentRulesetMidSessionEdit,
    /// A host<->sandbox sync patch validated cleanly and was applied.
    SyncApplied,
    /// A host<->sandbox sync patch failed validation (malformed/corrupted,
    /// or re-introduced a blocklisted path) and was flagged for review
    /// instead of applied -- never silently merged or dropped.
    SyncFlagged,
    /// The local egress proxy let a guest connection through -- its SNI
    /// hostname matched the effective allowlist. Emitted for allowed
    /// connections too (not just denials) so a full connection trace is
    /// possible from the log alone.
    EgressAllowed,
    /// The local egress proxy refused a guest connection -- no SNI hostname
    /// could be read from its TLS ClientHello, or the hostname isn't on the
    /// allowlist. Fails closed either way; emitted before the connection is
    /// dropped, never after a best-effort forward.
    EgressDenied,
}

impl EventKind {
    pub fn tag(self) -> &'static str {
        match self {
            EventKind::PreflightFailure => "preflight-failure",
            EventKind::InstallFailure => "install-failure",
            EventKind::InstallAction => "install-action",
            EventKind::ContentRulesetMidSessionEdit => "content-ruleset-mid-session-edit",
            EventKind::SyncApplied => "sync-applied",
            EventKind::SyncFlagged => "sync-flagged",
            EventKind::EgressAllowed => "egress-allowed",
            EventKind::EgressDenied => "egress-denied",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// One boundary-audit event. `check` and `message` derive from probe output
/// (e.g. command stderr) and must never be assumed shell-safe.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub ts_unix_ms: u128,
    pub kind: EventKind,
    /// Name of the specific check that produced this event, if any (e.g.
    /// "kvm", "podman") -- `kind` is the event class, `check` is which
    /// check within that class.
    pub check: Option<String>,
    pub message: String,
}

impl AuditEvent {
    pub fn now(kind: EventKind, check: Option<&str>, message: impl Into<String>) -> Self {
        let ts_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        AuditEvent {
            ts_unix_ms,
            kind,
            check: check.map(|s| s.to_string()),
            message: message.into(),
        }
    }

    /// Render as one JSON-object line (JSON Lines format).
    pub fn to_json_line(&self) -> String {
        let check_field = match &self.check {
            Some(c) => format!("\"{}\"", json_escape(c)),
            None => "null".to_string(),
        };
        format!(
            "{{\"ts_unix_ms\":{},\"kind\":\"{}\",\"check\":{},\"message\":\"{}\"}}",
            self.ts_unix_ms,
            json_escape(self.kind.tag()),
            check_field,
            json_escape(&self.message),
        )
    }
}

/// Escape a string for embedding as a JSON string value. Hand-rolled (no
/// serde_json dependency available); tested against shell-metacharacter
/// payloads to confirm they come out as inert escaped text.
pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Where an `AuditEvent` is recorded. Abstracted so callers can be
/// unit-tested against an in-memory sink without touching the filesystem.
pub trait AuditSink {
    fn record(&self, event: &AuditEvent) -> io::Result<()>;
}

/// Appends one JSON line per event to a file, creating parent directories
/// and the file itself if needed. Never truncates -- the audit log is
/// append-only.
pub struct FileAuditSink {
    path: PathBuf,
}

impl FileAuditSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileAuditSink { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", event.to_json_line())
    }
}

/// In-memory sink, exposed (not test-only) so other crates' unit tests can
/// assert on exactly what was logged.
#[derive(Default)]
pub struct MemoryAuditSink {
    pub events: std::sync::Mutex<Vec<AuditEvent>>,
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kinds_have_distinct_tags() {
        assert_eq!(EventKind::PreflightFailure.tag(), "preflight-failure");
        assert_eq!(EventKind::InstallFailure.tag(), "install-failure");
        assert_eq!(EventKind::InstallAction.tag(), "install-action");
        assert_eq!(
            EventKind::ContentRulesetMidSessionEdit.tag(),
            "content-ruleset-mid-session-edit"
        );
        assert_ne!(
            EventKind::PreflightFailure.tag(),
            EventKind::InstallFailure.tag()
        );
        assert_ne!(
            EventKind::InstallAction.tag(),
            EventKind::InstallFailure.tag()
        );
        assert_ne!(
            EventKind::ContentRulesetMidSessionEdit.tag(),
            EventKind::InstallAction.tag()
        );
        assert_eq!(EventKind::SyncApplied.tag(), "sync-applied");
        assert_eq!(EventKind::SyncFlagged.tag(), "sync-flagged");
        assert_ne!(EventKind::SyncApplied.tag(), EventKind::SyncFlagged.tag());
        assert_eq!(EventKind::EgressAllowed.tag(), "egress-allowed");
        assert_eq!(EventKind::EgressDenied.tag(), "egress-denied");
        assert_ne!(
            EventKind::EgressAllowed.tag(),
            EventKind::EgressDenied.tag()
        );
    }

    #[test]
    fn shell_metacharacters_are_escaped_verbatim_not_executed() {
        let payloads = [
            "$(rm -rf /)",
            "`id`",
            "; rm -rf / ;",
            "\" ; cat /etc/passwd ; \"",
            "a\nb\tc\r",
        ];
        for payload in payloads {
            let event = AuditEvent::now(
                EventKind::PreflightFailure,
                Some(payload),
                payload.to_string(),
            );
            let line = event.to_json_line();

            assert!(
                !line.contains('\n') && !line.contains('\r') && !line.contains('\t'),
                "control characters leaked unescaped into: {line}"
            );
            assert!(line.starts_with('{') && line.ends_with('}'));
            assert!(line.contains("\"kind\":\"preflight-failure\""));
            assert!(line.contains(&json_escape(payload)));
        }
    }

    #[test]
    fn file_sink_appends_one_line_per_event_and_creates_parent_dirs() {
        let dir = std::env::temp_dir().join(format!(
            "habitat-audit-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let log_path = dir.join("nested").join("audit.log");
        let sink = FileAuditSink::new(&log_path);

        sink.record(&AuditEvent::now(
            EventKind::PreflightFailure,
            Some("kvm"),
            "no kvm",
        ))
        .unwrap();
        sink.record(&AuditEvent::now(
            EventKind::InstallFailure,
            Some("os"),
            "not linux",
        ))
        .unwrap();

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("preflight-failure"));
        assert!(lines[1].contains("install-failure"));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
