//! Black-box exit-gate tests for `habitat_workspace::agent_state`: what
//! crosses the host/sandbox boundary for agent auth and config state, in
//! which direction, and under which agent's scope. The guest is a
//! `FakeGuest` backed by a real temporary directory, so these exercise
//! the real filesystem logic end to end; the real `ssh`/`scp` round trip
//! is `tests/manual/validate-agent-state.sh`'s job.
//!
//! Hostile-guest behavior (oversized, malformed, symlinked, transport
//! failure) lives in `tests/adversarial/agent_state_copy_out.rs`.

use habitat_audit::{EventKind, MemoryAuditSink};
use habitat_workspace::agent_state::AgentStateSession;
use habitat_workspace::command_runner::testing::FakeGuest;
use habitat_workspace::guest_exec::{GuestEndpoint, GuestExecRunner};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const GUEST_HOME: &str = "/home/habitat";

struct Env {
    root: PathBuf,
    home: PathBuf,
    guest: FakeGuest,
    key: PathBuf,
}

impl Env {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "habitat-agent-state-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let guest = FakeGuest::new(root.join("guest"));
        Env {
            key: root.join("key"),
            root,
            home,
            guest,
        }
    }

    fn endpoint(&self) -> GuestEndpoint<'_> {
        GuestEndpoint {
            host: "127.0.0.1",
            port: 2222,
            private_key_path: &self.key,
        }
    }

    fn host_file(&self, agent: &str, rel: &str, contents: &str) -> PathBuf {
        let p = self.home.join(".habitat/agents").join(agent).join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, contents).unwrap();
        p
    }

    fn host_read(&self, agent: &str, rel: &str) -> Option<String> {
        fs::read_to_string(self.home.join(".habitat/agents").join(agent).join(rel)).ok()
    }

    fn guest_path(rel: &str) -> String {
        format!("{GUEST_HOME}/{rel}")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn audit_tags(audit: &MemoryAuditSink) -> Vec<&'static str> {
    audit
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|e| e.kind.tag())
        .collect()
}

#[test]
fn open_creates_the_host_directories_private() {
    let env = Env::new("dirs");
    let _s = AgentStateSession::open(&env.home, &["claude"], GUEST_HOME).unwrap();
    assert_eq!(mode(&env.home.join(".habitat")), 0o700);
    assert_eq!(mode(&env.home.join(".habitat/agents")), 0o700);
    assert_eq!(mode(&env.home.join(".habitat/agents/claude")), 0o700);
}

#[test]
fn open_tightens_loose_existing_directories() {
    let env = Env::new("tighten");
    let habitat = env.home.join(".habitat");
    fs::create_dir_all(habitat.join("agents/claude")).unwrap();
    for d in [
        habitat.clone(),
        habitat.join("agents"),
        habitat.join("agents/claude"),
    ] {
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let _s = AgentStateSession::open(&env.home, &["claude"], GUEST_HOME).unwrap();
    assert_eq!(mode(&habitat), 0o700);
    assert_eq!(mode(&habitat.join("agents")), 0o700);
    assert_eq!(mode(&habitat.join("agents/claude")), 0o700);
}

#[test]
fn copy_in_copies_auth_and_config_and_skips_whatever_is_missing() {
    let env = Env::new("in");
    env.host_file("claude", ".claude/.credentials.json", "{\"tok\":1}");
    env.host_file("claude", ".claude.json", "{\"onboarded\":true}");
    env.host_file("claude", ".claude/settings.json", "{\"theme\":\"dark\"}");
    env.host_file("claude", ".claude/commands/review.md", "review things");
    // CLAUDE.md, agents/ and skills/ deliberately absent.

    let s = AgentStateSession::open(&env.home, &["claude"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    let report = s.copy_in(&guest, &audit);

    assert!(report.is_clean(), "{report:?}");
    assert_eq!(report.copied.len(), 4, "{report:?}");
    assert_eq!(
        env.guest
            .read(&Env::guest_path(".claude/.credentials.json"))
            .unwrap(),
        b"{\"tok\":1}"
    );
    assert_eq!(
        env.guest.read(&Env::guest_path(".claude.json")).unwrap(),
        b"{\"onboarded\":true}"
    );
    assert_eq!(
        env.guest
            .read(&Env::guest_path(".claude/settings.json"))
            .unwrap(),
        b"{\"theme\":\"dark\"}"
    );
    assert_eq!(
        env.guest
            .read(&Env::guest_path(".claude/commands/review.md"))
            .unwrap(),
        b"review things"
    );
    assert!(!env.guest.exists(&Env::guest_path(".claude/CLAUDE.md")));
    // Auth files are tightened in the guest; config keeps its own mode.
    assert_eq!(
        mode(
            &env.guest
                .path(&Env::guest_path(".claude/.credentials.json"))
        ),
        0o600
    );
    assert_eq!(
        mode(&env.guest.path(&Env::guest_path(".claude.json"))),
        0o600
    );
}

#[test]
fn a_named_agent_session_only_ever_receives_that_agents_files() {
    let env = Env::new("scope");
    env.host_file("claude", ".claude/.credentials.json", "{\"claude\":1}");
    env.host_file("codex", ".codex/auth.json", "{\"codex\":1}");
    env.host_file("opencode", ".local/share/opencode/auth.json", "{\"oc\":1}");

    let s = AgentStateSession::open(&env.home, &["claude"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    let report = s.copy_in(&guest, &audit);

    assert_eq!(
        report.copied,
        vec!["claude:.claude/.credentials.json".to_string()]
    );
    assert!(!env.guest.exists(&Env::guest_path(".codex/auth.json")));
    assert!(!env
        .guest
        .exists(&Env::guest_path(".local/share/opencode/auth.json")));
    assert_eq!(s.agents(), vec!["claude"]);
}

#[test]
fn a_shell_session_receives_every_agents_files() {
    let env = Env::new("shell");
    env.host_file("claude", ".claude/.credentials.json", "{\"claude\":1}");
    env.host_file("codex", ".codex/auth.json", "{\"codex\":1}");
    env.host_file("opencode", ".local/share/opencode/auth.json", "{\"oc\":1}");
    env.host_file(
        "opencode",
        ".local/share/opencode/mcp-auth.json",
        "{\"mcp\":1}",
    );
    env.host_file("opencode", ".config/opencode/opencode.json", "{}");

    let s =
        AgentStateSession::open(&env.home, &["claude", "codex", "opencode"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    let report = s.copy_in(&guest, &audit);

    assert!(report.is_clean(), "{report:?}");
    assert_eq!(report.copied.len(), 5, "{report:?}");
    assert!(env.guest.exists(&Env::guest_path(".codex/auth.json")));
    assert!(env
        .guest
        .exists(&Env::guest_path(".local/share/opencode/mcp-auth.json")));
    assert!(env
        .guest
        .exists(&Env::guest_path(".config/opencode/opencode.json")));
}

#[test]
fn copy_out_brings_back_a_refreshed_token() {
    let env = Env::new("refresh");
    env.host_file("codex", ".codex/auth.json", "{\"refresh\":\"old\"}");
    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    s.copy_in(&guest, &audit);

    // The agent refreshes its token inside the guest.
    env.guest.write(
        &Env::guest_path(".codex/auth.json"),
        b"{\"refresh\":\"new\"}",
    );
    let report = s.copy_out(&guest, &audit);

    assert!(report.is_clean(), "{report:?}");
    assert_eq!(report.copied, vec!["codex:.codex/auth.json".to_string()]);
    assert_eq!(
        env.host_read("codex", ".codex/auth.json").unwrap(),
        "{\"refresh\":\"new\"}"
    );
    assert_eq!(
        mode(&env.home.join(".habitat/agents/codex/.codex/auth.json")),
        0o600
    );
}

#[test]
fn a_first_login_inside_the_guest_is_created_on_the_host_private() {
    let env = Env::new("firstlogin");
    let s = AgentStateSession::open(&env.home, &["opencode"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    assert!(s.copy_in(&guest, &audit).copied.is_empty());

    env.guest.write(
        &Env::guest_path(".local/share/opencode/auth.json"),
        b"{\"anthropic\":{\"key\":\"k\"}}",
    );
    let report = s.copy_out(&guest, &audit);

    assert_eq!(report.copied.len(), 1, "{report:?}");
    let host = env
        .home
        .join(".habitat/agents/opencode/.local/share/opencode/auth.json");
    assert_eq!(
        fs::read_to_string(&host).unwrap(),
        "{\"anthropic\":{\"key\":\"k\"}}"
    );
    assert_eq!(mode(&host), 0o600);
    assert_eq!(mode(host.parent().unwrap()), 0o700);
}

#[test]
fn config_files_are_never_copied_back_out() {
    let env = Env::new("configoneway");
    env.host_file("claude", ".claude/settings.json", "{\"hooks\":\"host\"}");
    env.host_file("claude", ".claude/commands/a.md", "host a");
    let s = AgentStateSession::open(&env.home, &["claude"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    s.copy_in(&guest, &audit);

    // A compromised session rewrites config and plants a new hook script.
    env.guest.write(
        &Env::guest_path(".claude/settings.json"),
        b"{\"hooks\":\"evil\"}",
    );
    env.guest
        .write(&Env::guest_path(".claude/commands/a.md"), b"evil a");
    env.guest
        .write(&Env::guest_path(".claude/commands/new.md"), b"planted");
    env.guest.write(
        &Env::guest_path(".claude/CLAUDE.md"),
        b"planted instructions",
    );
    let report = s.copy_out(&guest, &audit);

    assert!(report.copied.is_empty(), "{report:?}");
    assert_eq!(
        env.host_read("claude", ".claude/settings.json").unwrap(),
        "{\"hooks\":\"host\"}"
    );
    assert_eq!(
        env.host_read("claude", ".claude/commands/a.md").unwrap(),
        "host a"
    );
    assert!(env.host_read("claude", ".claude/commands/new.md").is_none());
    assert!(env.host_read("claude", ".claude/CLAUDE.md").is_none());
}

#[test]
fn files_outside_the_manifest_never_reach_the_host() {
    let env = Env::new("outside");
    let s = AgentStateSession::open(&env.home, &["claude"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    env.guest.write(
        &Env::guest_path(".claude/projects/-workspace/transcript.jsonl"),
        b"{\"secret\":1}",
    );
    env.guest.write(
        &Env::guest_path(".ssh/authorized_keys"),
        b"ssh-ed25519 AAAA",
    );
    env.guest
        .write(&Env::guest_path(".gitconfig"), b"[core]\nfsmonitor = x");
    s.copy_out(&guest, &audit);

    let agent_dir = env.home.join(".habitat/agents/claude");
    let mut stack = vec![agent_dir.clone()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                assert_eq!(
                    p.file_name().unwrap(),
                    ".lock",
                    "unexpected host file {p:?}"
                );
            }
        }
    }
}

#[test]
fn an_unchanged_file_is_not_rewritten_or_relogged() {
    let env = Env::new("unchanged");
    env.host_file("codex", ".codex/auth.json", "{\"t\":1}");
    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    s.copy_in(&guest, &audit);
    let before = audit.events.lock().unwrap().len();

    let first = s.copy_out(&guest, &audit);
    let second = s.copy_out(&guest, &audit);

    assert!(first.copied.is_empty() && second.copied.is_empty());
    assert_eq!(
        audit.events.lock().unwrap().len(),
        before,
        "no new audit events expected"
    );
}

#[test]
fn a_missing_guest_file_never_deletes_the_host_copy() {
    let env = Env::new("nodelete");
    env.host_file("codex", ".codex/auth.json", "{\"t\":1}");
    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    s.copy_in(&guest, &audit);
    fs::remove_file(env.guest.path(&Env::guest_path(".codex/auth.json"))).unwrap();

    let report = s.copy_out(&guest, &audit);

    assert!(report.copied.is_empty() && report.is_clean(), "{report:?}");
    assert_eq!(
        env.host_read("codex", ".codex/auth.json").unwrap(),
        "{\"t\":1}"
    );
}

#[test]
fn no_temp_files_are_left_behind_after_copy_out() {
    let env = Env::new("notemp");
    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    env.guest
        .write(&Env::guest_path(".codex/auth.json"), b"{\"t\":2}");
    s.copy_out(&guest, &audit);
    let names: Vec<String> = fs::read_dir(env.home.join(".habitat/agents/codex/.codex"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["auth.json".to_string()]);
}

#[test]
fn a_second_concurrent_session_copies_in_but_never_out() {
    let env = Env::new("lock");
    env.host_file("codex", ".codex/auth.json", "{\"t\":\"original\"}");
    let first = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let second = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    assert!(first.holds_lock("codex"));
    assert!(!second.holds_lock("codex"));

    // Second session still authenticates...
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    assert_eq!(second.copy_in(&guest, &audit).copied.len(), 1);

    // ...but must not overwrite the lock holder's token with its own.
    env.guest.write(
        &Env::guest_path(".codex/auth.json"),
        b"{\"t\":\"from-second\"}",
    );
    let report = second.copy_out(&guest, &audit);
    assert_eq!(report.rejected.len(), 1, "{report:?}");
    assert_eq!(
        env.host_read("codex", ".codex/auth.json").unwrap(),
        "{\"t\":\"original\"}"
    );

    // The notice is logged once, not on every tick.
    let again = second.copy_out(&guest, &audit);
    assert!(again.rejected.is_empty(), "{again:?}");
    let rejected = audit_tags(&audit)
        .iter()
        .filter(|t| **t == "agent-state-rejected")
        .count();
    assert_eq!(rejected, 1);
}

#[test]
fn the_lock_is_released_when_the_session_is_dropped() {
    let env = Env::new("lockrelease");
    {
        let first = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
        assert!(first.holds_lock("codex"));
    }
    let next = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    assert!(next.holds_lock("codex"));
}

#[test]
fn audit_records_paths_and_fingerprints_but_never_file_contents() {
    let env = Env::new("audit");
    env.host_file(
        "codex",
        ".codex/auth.json",
        "{\"access_token\":\"SUPERSECRETTOKEN\"}",
    );
    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    s.copy_in(&guest, &audit);
    env.guest.write(
        &Env::guest_path(".codex/auth.json"),
        b"{\"access_token\":\"ANOTHERSECRET\"}",
    );
    s.copy_out(&guest, &audit);

    let events = audit.events.lock().unwrap();
    assert!(events
        .iter()
        .any(|e| e.kind == EventKind::AgentStateCopiedIn));
    assert!(events
        .iter()
        .any(|e| e.kind == EventKind::AgentStateCopiedOut));
    for e in events.iter() {
        assert!(
            !e.message.contains("SECRET"),
            "audit leaked content: {}",
            e.message
        );
        assert!(e.message.contains("agent=codex"), "{}", e.message);
    }
}

#[test]
fn agent_state_events_are_never_suppressible() {
    for kind in [
        EventKind::AgentStateCopiedIn,
        EventKind::AgentStateCopiedOut,
        EventKind::AgentStateRejected,
    ] {
        assert!(
            !kind.is_suppressible_when_audit_disabled(),
            "{kind} must stay visible even with `audit: disabled`"
        );
    }
}
