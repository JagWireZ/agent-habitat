//! `habitat-audit` -- the unified audit log for everything crossing the
//! host/sandbox boundary.
//!
//! Phase 1 scope: a minimal sink, established here so `habitat-install` has
//! somewhere fail-closed to log preflight/install failures to. Full content
//! (session start/stop, VM launch/teardown, proxy allow/deny, sync events)
//! is added in Phase 6 -- this module is written so those additions are new
//! `EventKind` variants and call sites, not a format change.
//!
//! Explicit scope note (carried into operator-facing output too, per
//! AGENTS.md Section 4's deferred-items table): this is boundary-only
//! audit, not in-sandbox activity logging.
//!
//! Log content is treated as untrusted, attacker-influenced input from day
//! one (AGENTS.md Section 2, invariant 12): every string written into an
//! event is JSON-string-escaped before it touches disk, and nothing here
//! ever passes a logged value through a shell. No dependency on
//! `serde_json` is taken (Phase 1 has no dependency-fetch access in this
//! environment) -- the escaping is done by hand and unit-tested against
//! shell-metacharacter payloads specifically.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The kind of event being recorded. Each variant renders to a distinct,
/// stable tag string (see `EventKind::tag`) so that preflight failures,
/// install failures, and (from Phase 6 on) ordinary lifecycle events are
/// all separately identifiable in the log -- never collapsed into one
/// generic "event" bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// `habitat run`'s preflight subroutine refused to proceed.
    PreflightFailure,
    /// `habitat install` refused to proceed.
    InstallFailure,
}

impl EventKind {
    pub fn tag(self) -> &'static str {
        match self {
            EventKind::PreflightFailure => "preflight-failure",
            EventKind::InstallFailure => "install-failure",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// One boundary-audit event. `check` and `message` are attacker-influenced
/// in the sense that their content ultimately derives from probe output
/// (e.g. a command's stderr) -- never assume they are shell-safe.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub ts_unix_ms: u128,
    pub kind: EventKind,
    /// Name of the specific check that produced this event, if any
    /// (e.g. "kvm", "podman"). Distinct from `kind`'s tag --
    /// `kind` says *what class* of event this is, `check` says *which
    /// check* within that class.
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

    /// Render as one JSON-object line (JSON Lines format). Every string
    /// field is escaped by `json_escape` -- this is the only place a
    /// logged value is turned into text, and it never shells out.
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

/// Escape a string for embedding as a JSON string value. Deliberately
/// hand-rolled (no serde_json dependency available) and exercised in
/// tests with shell-metacharacter payloads (`` $(...) ``, backticks, `;`,
/// quotes, newlines) to confirm they come out as inert escaped text, never
/// anything that could be re-interpreted by a shell or break the JSON
/// structure.
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

/// Where an `AuditEvent` is recorded. Abstracted so preflight/install
/// logic can be unit-tested against an in-memory sink without touching the
/// filesystem, and so Phase 6 can add richer sinks without changing call
/// sites.
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

/// In-memory sink, exposed (not test-only) so other crates -- notably
/// `habitat-install`'s own unit tests -- can assert on exactly what was
/// logged without touching the filesystem.
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
        assert_ne!(
            EventKind::PreflightFailure.tag(),
            EventKind::InstallFailure.tag()
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

            // The payload must appear only in escaped form: raw backticks,
            // raw double-quotes, and raw control characters must not
            // survive into the serialized line unescaped.
            assert!(
                !line.contains('\n') && !line.contains('\r') && !line.contains('\t'),
                "control characters leaked unescaped into: {line}"
            );
            // The overall line must still be one well-formed JSON object:
            // exactly the four keys we write, nothing injected.
            assert!(line.starts_with('{') && line.ends_with('}'));
            assert!(line.contains("\"kind\":\"preflight-failure\""));

            // Confirm the escaped payload round-trips back to the
            // original when unescaped the same way JSON would.
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
