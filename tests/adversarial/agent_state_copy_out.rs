//! Adversarial tests for agent-state copying: the guest is hostile on the
//! way back out, and the host filesystem under `~/.habitat/agents` may
//! contain things the code must not follow. Each test pins one way a
//! compromised session (or a stray symlink) could try to turn a
//! credential-sync mechanism into something else.
//!
//! Mirrors `tests/unit/workspace/agent_state_exit_gate.rs`, which covers the
//! well-behaved paths.

use habitat_audit::{EventKind, MemoryAuditSink};
use habitat_workspace::agent_state::{
    AgentStateSession, MAX_AUTH_FILE_BYTES, MAX_CONFIG_FILES_PER_DIR,
};
use habitat_workspace::command_runner::testing::FakeGuest;
use habitat_workspace::guest_exec::{GuestEndpoint, GuestExecRunner};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

const GUEST_HOME: &str = "/home/habitat";
const GOOD: &str = "{\"refresh\":\"good\"}";

struct Env {
    root: PathBuf,
    home: PathBuf,
    guest: FakeGuest,
    key: PathBuf,
}

impl Env {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "habitat-agent-state-adv-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        Env {
            guest: FakeGuest::new(root.join("guest")),
            key: root.join("key"),
            root,
            home,
        }
    }

    fn endpoint(&self) -> GuestEndpoint<'_> {
        GuestEndpoint {
            host: "127.0.0.1",
            port: 2222,
            private_key_path: &self.key,
        }
    }

    fn host(&self, agent: &str, rel: &str) -> PathBuf {
        self.home.join(".habitat/agents").join(agent).join(rel)
    }

    fn host_file(&self, agent: &str, rel: &str, contents: &[u8]) -> PathBuf {
        let p = self.host(agent, rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, contents).unwrap();
        p
    }

    fn gpath(rel: &str) -> String {
        format!("{GUEST_HOME}/{rel}")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn rejections(audit: &MemoryAuditSink) -> usize {
    audit
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.kind == EventKind::AgentStateRejected)
        .count()
}

/// Sets up a session where the host already holds a good codex token that
/// was copied in, then lets the test corrupt the guest copy.
fn codex_with_good_token(env: &Env) -> (AgentStateSession, MemoryAuditSink) {
    env.host_file("codex", ".codex/auth.json", GOOD.as_bytes());
    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    assert!(s.copy_in(&guest, &audit).is_clean());
    (s, audit)
}

fn assert_host_token_untouched(env: &Env) {
    assert_eq!(
        fs::read_to_string(env.host("codex", ".codex/auth.json")).unwrap(),
        GOOD
    );
}

#[test]
fn an_oversized_file_from_the_guest_is_rejected_and_the_host_copy_survives() {
    let env = Env::new("oversize");
    let (s, audit) = codex_with_good_token(&env);
    let mut big = b"{\"pad\":\"".to_vec();
    big.extend(std::iter::repeat_n(b'a', MAX_AUTH_FILE_BYTES + 100));
    big.extend_from_slice(b"\"}");
    env.guest.write(&Env::gpath(".codex/auth.json"), &big);

    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    let report = s.copy_out(&guest, &audit);

    assert_eq!(report.rejected.len(), 1, "{report:?}");
    assert_host_token_untouched(&env);
}

#[test]
fn malformed_empty_or_non_object_json_never_replaces_a_good_token() {
    let env = Env::new("malformed");
    let (s, audit) = codex_with_good_token(&env);
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());

    let attempts: [&[u8]; 6] = [
        b"",
        b"not json at all",
        b"{\"truncated\":",
        b"[\"array\",\"not\",\"object\"]",
        b"null",
        b"\xff\xfe\x00binary",
    ];
    for attempt in attempts {
        env.guest.write(&Env::gpath(".codex/auth.json"), attempt);
        let report = s.copy_out(&guest, &audit);
        assert_eq!(report.rejected.len(), 1, "{attempt:?} -> {report:?}");
        assert!(report.copied.is_empty());
        assert_host_token_untouched(&env);
    }
}

#[test]
fn a_persistently_bad_file_is_logged_once_not_every_tick() {
    let env = Env::new("dedup");
    let (s, audit) = codex_with_good_token(&env);
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    env.guest.write(&Env::gpath(".codex/auth.json"), b"garbage");

    for _ in 0..10 {
        s.copy_out(&guest, &audit);
    }
    assert_eq!(rejections(&audit), 1);

    // A *different* bad payload is news and is logged again.
    env.guest
        .write(&Env::gpath(".codex/auth.json"), b"other garbage");
    s.copy_out(&guest, &audit);
    assert_eq!(rejections(&audit), 2);
}

#[test]
fn a_good_file_after_a_bad_one_is_accepted_again() {
    let env = Env::new("recover");
    let (s, audit) = codex_with_good_token(&env);
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    env.guest.write(&Env::gpath(".codex/auth.json"), b"garbage");
    s.copy_out(&guest, &audit);

    env.guest
        .write(&Env::gpath(".codex/auth.json"), b"{\"refresh\":\"fixed\"}");
    let report = s.copy_out(&guest, &audit);

    assert_eq!(report.copied.len(), 1, "{report:?}");
    assert_eq!(
        fs::read_to_string(env.host("codex", ".codex/auth.json")).unwrap(),
        "{\"refresh\":\"fixed\"}"
    );
}

#[test]
fn a_transport_failure_is_reported_and_changes_nothing_on_the_host() {
    let env = Env::new("transport");
    let (s, audit) = codex_with_good_token(&env);
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    env.guest
        .write(&Env::gpath(".codex/auth.json"), b"{\"refresh\":\"new\"}");
    env.guest.transport_down.store(true, Ordering::Relaxed);

    let report = s.copy_out(&guest, &audit);

    assert_eq!(report.rejected.len(), 1, "{report:?}");
    assert_host_token_untouched(&env);
}

#[test]
fn copy_in_survives_a_dead_transport_without_panicking_or_partial_state() {
    let env = Env::new("indead");
    env.host_file("codex", ".codex/auth.json", GOOD.as_bytes());
    env.host_file("codex", ".codex/config.toml", b"a = 1\n");
    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    env.guest.transport_down.store(true, Ordering::Relaxed);

    let report = s.copy_in(&guest, &audit);

    assert!(report.copied.is_empty());
    assert_eq!(report.rejected.len(), 2, "{report:?}");
    assert!(!env.guest.exists(&Env::gpath(".codex/auth.json")));
}

#[test]
fn copy_out_never_writes_through_a_symlink_at_the_destination() {
    let env = Env::new("destlink");
    let victim = env.root.join("victim.txt");
    fs::write(&victim, "precious").unwrap();
    let dest = env.host("codex", ".codex/auth.json");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    symlink(&victim, &dest).unwrap();

    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    env.guest
        .write(&Env::gpath(".codex/auth.json"), b"{\"a\":1}");
    let report = s.copy_out(&guest, &audit);

    assert_eq!(report.rejected.len(), 1, "{report:?}");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    assert!(fs::symlink_metadata(&dest)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn copy_in_refuses_a_symlinked_source_instead_of_following_it() {
    let env = Env::new("srclink");
    let secret = env.root.join("host-secret.txt");
    fs::write(&secret, "ssh private key material").unwrap();
    let src = env.host("codex", ".codex/auth.json");
    fs::create_dir_all(src.parent().unwrap()).unwrap();
    symlink(&secret, &src).unwrap();

    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    let report = s.copy_in(&guest, &audit);

    assert_eq!(report.rejected.len(), 1, "{report:?}");
    assert!(!env.guest.exists(&Env::gpath(".codex/auth.json")));
}

#[test]
fn a_symlink_inside_a_config_directory_rejects_that_directory_only() {
    let env = Env::new("treelink");
    let secret = env.root.join("host-secret.txt");
    fs::write(&secret, "do not leak").unwrap();
    env.host_file("claude", ".claude/skills/ok/SKILL.md", b"fine");
    symlink(&secret, env.host("claude", ".claude/skills/leak.md")).unwrap();
    env.host_file("claude", ".claude/commands/c.md", b"command");
    env.host_file("claude", ".claude/.credentials.json", GOOD.as_bytes());

    let s = AgentStateSession::open(&env.home, &["claude"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    let report = s.copy_in(&guest, &audit);

    assert_eq!(report.rejected.len(), 1, "{report:?}");
    assert!(report.rejected[0].0.contains("skills"));
    // Nothing from the poisoned directory arrived, symlink target included.
    assert!(!env.guest.exists(&Env::gpath(".claude/skills")));
    // Everything else still did.
    assert!(env.guest.exists(&Env::gpath(".claude/commands/c.md")));
    assert!(env.guest.exists(&Env::gpath(".claude/.credentials.json")));
}

#[test]
fn a_config_directory_over_the_file_limit_is_rejected() {
    let env = Env::new("toomany");
    for i in 0..=MAX_CONFIG_FILES_PER_DIR {
        env.host_file("codex", &format!(".codex/skills/s{i}.md"), b"x");
    }
    let s = AgentStateSession::open(&env.home, &["codex"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    let report = s.copy_in(&guest, &audit);

    assert_eq!(report.rejected.len(), 1, "{report:?}");
    assert!(!env.guest.exists(&Env::gpath(".codex/skills")));
}

#[test]
fn a_directory_where_a_file_is_expected_is_rejected() {
    let env = Env::new("wrongtype");
    fs::create_dir_all(env.host("claude", ".claude.json")).unwrap();
    let s = AgentStateSession::open(&env.home, &["claude"], GUEST_HOME).unwrap();
    let audit = MemoryAuditSink::default();
    let guest = GuestExecRunner::new(&env.guest, env.endpoint());
    let report = s.copy_in(&guest, &audit);
    assert_eq!(report.rejected.len(), 1, "{report:?}");
}

#[test]
fn open_refuses_a_symlinked_agents_directory() {
    let env = Env::new("agentslink");
    let elsewhere = env.root.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(env.home.join(".habitat")).unwrap();
    symlink(&elsewhere, env.home.join(".habitat/agents")).unwrap();
    assert!(AgentStateSession::open(&env.home, &["claude"], GUEST_HOME).is_err());
}

#[test]
fn open_rejects_a_relative_home_and_a_malformed_guest_home() {
    let env = Env::new("badargs");
    assert!(
        AgentStateSession::open(std::path::Path::new("relative"), &["claude"], GUEST_HOME).is_err()
    );
    assert!(AgentStateSession::open(&env.home, &["claude"], "home/habitat").is_err());
    assert!(AgentStateSession::open(&env.home, &["claude"], "/home/habitat/").is_err());
}

#[test]
fn an_agent_with_no_manifest_entries_gets_nothing_and_creates_nothing() {
    let env = Env::new("unknownagent");
    let s = AgentStateSession::open(&env.home, &["not-an-agent"], GUEST_HOME).unwrap();
    assert!(s.agents().is_empty());
    assert!(!env.home.join(".habitat/agents/not-an-agent").exists());
}
