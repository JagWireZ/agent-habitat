//! `habitat-audit` -- the unified audit log for everything crossing the
//! host/sandbox boundary. Boundary-only; in-sandbox activity is out of
//! scope.
//!
//! **Scope note:** this log records events at the host/sandbox boundary --
//! session start/stop, preflight/install pass/fail, egress allow/deny,
//! sync applied/flagged -- never what an agent ran or produced *inside*
//! the guest. Full in-sandbox activity logging is an explicitly deferred
//! feature (AGENTS.md §4); nothing in this crate is a step toward it, and
//! an operator should not read a clean audit log as "nothing happened in
//! the sandbox," only as "nothing crossed the boundary unexpectedly."
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
    /// `habitat run`'s preflight subroutine completed with every check
    /// green. The failure half (`PreflightFailure`) already existed from
    /// Phase 1; this is its missing "pass" counterpart, needed so a clean
    /// run is visible in the log at all, not just failures.
    PreflightPass,
    /// `habitat install` completed with every check green -- the "pass"
    /// counterpart to `InstallFailure`, same reasoning as `PreflightPass`.
    InstallPass,
    /// A session's microVM launch was attempted (`launcher::launch`
    /// entered, before `podman run` is invoked). Marks the start of a
    /// session's lifecycle in the log even if the launch itself then
    /// fails -- an attempt is boundary-relevant on its own.
    SessionStart,
    /// A session's teardown (`launcher::teardown`) completed: container
    /// force-removed, disk image deleted, SSH keypair deleted. Marks the
    /// end of a session's lifecycle. There is no separate
    /// `VmLaunch`/`VmTeardown` pair -- in this codebase a "session" *is*
    /// exactly the span between one launch and one teardown, so a second
    /// event pair with identical timing would just be a second name for
    /// the same fact.
    SessionStop,
    /// `habitat_workspace::sync::merge_workspace_commits_to_host` replayed
    /// one or more workspace-repo commits onto a brand-new `habitat/<ts>`
    /// branch in the project's real repo. Distinct from `SyncApplied`:
    /// that's a per-round working-tree patch, this is a deliberate,
    /// on-demand (or end-of-session) commit-granular merge that never
    /// touches the operator's checked-out branch.
    GitMergeApplied,
    /// A `merge_workspace_commits_to_host` call found new commits to bring
    /// in but failed partway through (e.g. a cherry-pick conflict) --
    /// always logged, and always left the project's real branches
    /// untouched (the throwaway branch/worktree are cleaned up, never
    /// left half-built).
    GitMergeFailed,
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
            EventKind::PreflightPass => "preflight-pass",
            EventKind::InstallPass => "install-pass",
            EventKind::SessionStart => "session-start",
            EventKind::SessionStop => "session-stop",
            EventKind::GitMergeApplied => "git-merge-applied",
            EventKind::GitMergeFailed => "git-merge-failed",
        }
    }

    /// Whether this event kind may be dropped when a project's config sets
    /// `audit: disabled` (`habitat_policy::config::ProjectConfig::audit`,
    /// Phase 7). Scoped deliberately narrow: only routine, low-signal
    /// events that duplicate information already implied by their absence
    /// (a clean preflight, an allowed connection, a cleanly-applied sync,
    /// an install action already surfaced to the operator interactively).
    /// AGENTS.md invariants 3, 10, 11, and 12 all assume a preflight
    /// failure, a flagged patch, an egress denial, a mid-session ruleset
    /// edit, and a session's start/stop are always visible in the audit
    /// trail -- so none of those may ever answer `true` here, regardless
    /// of config. See `docs/decisions/0009-run-driver-prompt-loop.md`.
    pub fn is_suppressible_when_audit_disabled(self) -> bool {
        match self {
            EventKind::PreflightPass
            | EventKind::InstallPass
            | EventKind::SyncApplied
            | EventKind::EgressAllowed
            | EventKind::InstallAction => true,
            EventKind::PreflightFailure
            | EventKind::InstallFailure
            | EventKind::ContentRulesetMidSessionEdit
            | EventKind::SyncFlagged
            | EventKind::EgressDenied
            | EventKind::SessionStart
            | EventKind::SessionStop
            | EventKind::GitMergeApplied
            | EventKind::GitMergeFailed => false,
        }
    }

    /// Every variant, for exhaustiveness checks (e.g. tag uniqueness) --
    /// kept next to the enum so a newly added variant is an obvious two-line
    /// diff away from being covered, rather than silently missing.
    pub const ALL: &'static [EventKind] = &[
        EventKind::PreflightFailure,
        EventKind::InstallFailure,
        EventKind::InstallAction,
        EventKind::ContentRulesetMidSessionEdit,
        EventKind::SyncApplied,
        EventKind::SyncFlagged,
        EventKind::EgressAllowed,
        EventKind::EgressDenied,
        EventKind::PreflightPass,
        EventKind::InstallPass,
        EventKind::SessionStart,
        EventKind::SessionStop,
        EventKind::GitMergeApplied,
        EventKind::GitMergeFailed,
    ];
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

/// Lets a shared reference to any sink (including `&dyn AuditSink`) be used
/// anywhere an owned `S: AuditSink` is expected -- e.g. wrapping a sink a
/// caller doesn't want to give up ownership of, such as in
/// [`FilteringAuditSink`].
impl<S: AuditSink + ?Sized> AuditSink for &S {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        (**self).record(event)
    }
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

/// Wraps another sink, dropping events for which
/// `EventKind::is_suppressible_when_audit_disabled` is `true` when
/// `enabled` is `false`. When `enabled` is `true` this is a transparent
/// passthrough. The non-suppressible event set is fixed by `EventKind`
/// itself, not configurable here -- this type only ever narrows what a
/// config's `audit: disabled` can affect, never widens it.
pub struct FilteringAuditSink<S: AuditSink> {
    inner: S,
    enabled: bool,
}

impl<S: AuditSink> FilteringAuditSink<S> {
    pub fn new(inner: S, enabled: bool) -> Self {
        FilteringAuditSink { inner, enabled }
    }
}

impl<S: AuditSink> AuditSink for FilteringAuditSink<S> {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        if !self.enabled && event.kind.is_suppressible_when_audit_disabled() {
            return Ok(());
        }
        self.inner.record(event)
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
        assert_eq!(EventKind::SyncApplied.tag(), "sync-applied");
        assert_eq!(EventKind::SyncFlagged.tag(), "sync-flagged");
        assert_eq!(EventKind::EgressAllowed.tag(), "egress-allowed");
        assert_eq!(EventKind::EgressDenied.tag(), "egress-denied");
        assert_eq!(EventKind::PreflightPass.tag(), "preflight-pass");
        assert_eq!(EventKind::InstallPass.tag(), "install-pass");
        assert_eq!(EventKind::SessionStart.tag(), "session-start");
        assert_eq!(EventKind::SessionStop.tag(), "session-stop");
    }

    /// Exhaustive pairwise-uniqueness check over `EventKind::ALL`, so a
    /// future added variant that collides with an existing tag fails this
    /// test even if nobody remembers to hand-write a new assertion for it.
    #[test]
    fn every_event_kind_tag_is_pairwise_unique() {
        let tags: Vec<&str> = EventKind::ALL.iter().map(|k| k.tag()).collect();
        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "duplicate audit event tag: {a}");
                }
            }
        }
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
    fn invariant_critical_events_are_never_suppressible() {
        let never_suppressible = [
            EventKind::PreflightFailure,
            EventKind::InstallFailure,
            EventKind::ContentRulesetMidSessionEdit,
            EventKind::SyncFlagged,
            EventKind::EgressDenied,
            EventKind::SessionStart,
            EventKind::SessionStop,
        ];
        for kind in never_suppressible {
            assert!(
                !kind.is_suppressible_when_audit_disabled(),
                "{kind} must never be suppressible"
            );
        }
    }

    #[test]
    fn filtering_sink_passes_everything_through_when_enabled() {
        let inner = MemoryAuditSink::default();
        let sink = FilteringAuditSink::new(&inner, true);
        sink.record(&AuditEvent::now(EventKind::PreflightPass, None, "ok"))
            .unwrap();
        sink.record(&AuditEvent::now(EventKind::SessionStart, None, "start"))
            .unwrap();
        assert_eq!(inner.events.lock().unwrap().len(), 2);
    }

    #[test]
    fn filtering_sink_drops_only_suppressible_events_when_disabled() {
        let inner = MemoryAuditSink::default();
        let sink = FilteringAuditSink::new(&inner, false);
        sink.record(&AuditEvent::now(EventKind::PreflightPass, None, "ok"))
            .unwrap();
        sink.record(&AuditEvent::now(EventKind::SyncApplied, None, "applied"))
            .unwrap();
        sink.record(&AuditEvent::now(
            EventKind::PreflightFailure,
            None,
            "failed",
        ))
        .unwrap();
        sink.record(&AuditEvent::now(EventKind::SessionStart, None, "start"))
            .unwrap();

        let events = inner.events.lock().unwrap();
        assert_eq!(events.len(), 2, "only the two non-suppressible events");
        assert_eq!(events[0].kind.tag(), "preflight-failure");
        assert_eq!(events[1].kind.tag(), "session-start");
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
