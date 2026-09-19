//! Phase 7 exit gate: "every documented config key is walked and
//! confirmed unable to bypass an invariant." Each test below covers one
//! `habitat_policy::config::ProjectConfig` field reaching its real
//! consumer (through `habitat_cli::run`'s own mapping functions, or
//! `habitat-workspace`/`habitat-vm`'s lower-level APIs directly) and
//! confirms no value it can hold weakens containment, blocklist
//! enforcement, patch validation, or the non-suppressible audit trail.
//!
//! `blocklist_additions`, `egress_allowlist_additions`, `git_history`, and
//! `secrets_scan` already have additive-only/hard-fail guarantees pinned
//! at the `habitat-policy`/`habitat-workspace` level (Phase 2's
//! `tests/adversarial/blocklist_disk_image.rs`, Phase 5's
//! `tests/adversarial/egress_bypass.rs`, `habitat_policy::git_history`'s
//! own unit tests) -- this file's job is confirming those guarantees
//! still hold reached through the real Phase 7 driver's config-to-request
//! mapping, not re-deriving them from scratch.

use habitat_audit::{AuditEvent, AuditSink, EventKind, FilteringAuditSink, MemoryAuditSink};
use habitat_cli::run::{self, SessionPaths};
use habitat_policy::blocklist;
use habitat_policy::config::ProjectConfig;
use habitat_policy::git_history::GitHistoryConfig;
use habitat_policy::resource_limits::ResourceLimitsConfig;
use habitat_policy::secrets_scan::Toggle;
use habitat_vm::launcher::build_run_args;
use habitat_vm::session::SessionId;
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::pipeline;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-config-invariants-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_via_driver(project_root: &std::path::Path, paths: &SessionPaths, config: &ProjectConfig) -> Result<(), String> {
    let request = run::build_request(project_root, paths, config);
    let runner = SystemCommandRunner;
    pipeline::build(request, &runner).map(|_| ()).map_err(|e| e.to_string())
}

/// `blocklist_additions`: additive only. A config can never cause a
/// default-blocked pattern to reach the disk image.
#[test]
fn blocklist_additions_cannot_remove_a_default_pattern() {
    let mut config = ProjectConfig::default();
    config.blocklist_additions = vec!["my-extra-pattern".to_string()];
    let effective = blocklist::effective_patterns(&config.blocklist_additions);
    for default in blocklist::default_patterns() {
        assert!(
            effective.contains(&default),
            "default pattern {default:?} must survive any config's additions"
        );
    }
}

/// `blocklist_additions` reached end-to-end through the real disk-build
/// pipeline: a `.env` file is still excluded even when the config only
/// *adds* an unrelated pattern.
#[test]
fn blocklist_additions_do_not_weaken_the_real_disk_build() {
    let project_root = temp_dir("blocklist-project");
    std::fs::write(project_root.join(".env"), "SECRET=leaked\n").unwrap();
    std::fs::write(project_root.join("real.txt"), "fine\n").unwrap();
    let state_dir = temp_dir("blocklist-state");
    let paths = SessionPaths::new(&state_dir);

    let mut config = ProjectConfig::default();
    config.blocklist_additions = vec!["*.mysecret".to_string()];
    config.secrets_scan.content = Toggle::Disabled;

    build_via_driver(&project_root, &paths, &config).expect("build must succeed");
    assert!(
        !paths.staging_dir().join(".env").exists(),
        "a default-blocked file must never reach staging regardless of config additions"
    );
    assert!(paths.staging_dir().join("real.txt").exists());

    std::fs::remove_dir_all(&project_root).unwrap();
    std::fs::remove_dir_all(&state_dir).unwrap();
}

/// `egress_allowlist_additions`: additive only, same shape as the
/// blocklist -- reached through `habitat_cli::run::effective_egress_allowlist`.
#[test]
fn egress_allowlist_additions_cannot_remove_a_default_entry() {
    let mut config = ProjectConfig::default();
    config.egress_allowlist_additions = vec!["internal.registry.example".to_string()];
    let effective = run::effective_egress_allowlist(&config);
    for default in habitat_policy::egress_allowlist::default_entries() {
        assert!(
            effective.contains(&default),
            "default allowlist entry {default:?} must survive any config's additions"
        );
    }
}

/// `git_history.enabled: true` without a complete, logged approval must
/// hard-fail the real build -- reached through the actual Phase 7 driver
/// mapping (`run::build_request`), not just the lower-level
/// `git_history::resolve` unit tests.
#[test]
fn git_history_enabled_without_approval_hard_fails_through_the_real_driver() {
    let project_root = temp_dir("git-history-project");
    std::fs::write(project_root.join("file.txt"), "hi\n").unwrap();
    let state_dir = temp_dir("git-history-state");
    let paths = SessionPaths::new(&state_dir);

    let mut config = ProjectConfig::default();
    config.git_history = GitHistoryConfig {
        enabled: true,
        approval: None,
    };
    config.secrets_scan.content = Toggle::Disabled;

    let result = build_via_driver(&project_root, &paths, &config);
    assert!(
        result.is_err(),
        "an unapproved git_history.enabled must never silently proceed"
    );
    assert!(
        !paths.staging_dir().exists(),
        "nothing should be staged at all once git history fails to resolve"
    );

    std::fs::remove_dir_all(&project_root).unwrap();
    std::fs::remove_dir_all(&state_dir).unwrap();
}

/// `secrets_scan.content: disabled` turns off the content scan only --
/// it must never also disable the independent filename blocklist
/// (`AGENTS.md` invariant 8: the two mechanisms are independent, neither
/// substitutes for the other).
#[test]
fn disabling_content_scan_does_not_disable_the_filename_blocklist() {
    let project_root = temp_dir("content-scan-project");
    std::fs::write(project_root.join(".env"), "SECRET=leaked\n").unwrap();
    let state_dir = temp_dir("content-scan-state");
    let paths = SessionPaths::new(&state_dir);

    let mut config = ProjectConfig::default();
    config.secrets_scan.content = Toggle::Disabled;
    assert!(
        config.secrets_scan.filenames.is_enabled(),
        "filenames must still default to enabled"
    );

    build_via_driver(&project_root, &paths, &config).expect("build must succeed");
    assert!(
        !paths.staging_dir().join(".env").exists(),
        "the filename blocklist must still apply even with content scanning off"
    );

    std::fs::remove_dir_all(&project_root).unwrap();
    std::fs::remove_dir_all(&state_dir).unwrap();
}

/// `resource_limits`: can only constrain CPU/memory, never grant an
/// elevated privilege or capability, regardless of the values a project
/// puts in its config -- reached through `run::launch_request`, not a
/// hand-built `LaunchRequest`.
#[test]
fn resource_limits_never_widen_launch_privileges() {
    let mut config = ProjectConfig::default();
    config.resource_limits = ResourceLimitsConfig {
        cpus: 64.0,
        memory_mb: 999_999,
    };
    let paths = SessionPaths::new("/tmp/habitat-config-invariants-resource-limits-state");
    let request = run::launch_request(
        SessionId::from_name("habitat-config-invariants-session").unwrap(),
        &paths,
        &config,
        "localhost/habitat-guest:alpine".to_string(),
        "127.0.0.1:8443".parse().unwrap(),
        "ssh-ed25519 AAAAtest".to_string(),
        PathBuf::from("/tmp/habitat-config-invariants-key"),
    );
    let args = build_run_args(&request);
    for forbidden in ["--privileged", "--cap-add", "--pid=host", "--network=host"] {
        assert!(
            !args.iter().any(|a| a == forbidden || a.starts_with(&format!("{forbidden}="))),
            "no resource_limits value may cause {forbidden} to appear: {args:?}"
        );
    }
    // Exactly the one expected workspace bind mount -- no resource_limits
    // value may cause a *second* one to appear.
    assert_eq!(
        args.iter().filter(|a| a.as_str() == "-v").count(),
        1,
        "no resource_limits value may cause an extra host bind mount: {args:?}"
    );
    assert!(
        !args.iter().any(|a| a == "--volume"),
        "no resource_limits value may cause a host bind mount via --volume: {args:?}"
    );
}

/// `audit: disabled` (Phase 7's own new key) may only suppress the
/// suppressible event set (`habitat_audit::EventKind::
/// is_suppressible_when_audit_disabled`) -- it must never suppress a
/// preflight failure, a flagged sync, an egress denial, or a session
/// start/stop, regardless of the rest of the config.
#[test]
fn audit_disabled_never_suppresses_invariant_critical_events() {
    let mut config = ProjectConfig::default();
    config.audit = Toggle::Disabled;
    assert!(!config.audit.is_enabled());

    let inner = MemoryAuditSink::default();
    let sink = FilteringAuditSink::new(&inner, config.audit.is_enabled());

    for kind in [
        EventKind::PreflightFailure,
        EventKind::InstallFailure,
        EventKind::SyncFlagged,
        EventKind::EgressDenied,
        EventKind::ContentRulesetMidSessionEdit,
        EventKind::SessionStart,
        EventKind::SessionStop,
    ] {
        sink.record(&AuditEvent::now(kind, None, "test")).unwrap();
    }
    let recorded: Vec<EventKind> = inner.events.lock().unwrap().iter().map(|e| e.kind).collect();
    assert_eq!(
        recorded.len(),
        7,
        "every invariant-critical event kind must survive audit: disabled: {recorded:?}"
    );
}

/// No config value threads into `build_run_args`/`network_setup` at all
/// beyond `resource_limits` (already checked above) -- every launch's
/// network flags are the same fixed, hardened `pasta`-based
/// configuration regardless of what a project's config contains.
#[test]
fn no_config_value_can_select_host_networking_or_an_unset_network_mode() {
    for config in [ProjectConfig::default(), {
        let mut c = ProjectConfig::default();
        c.egress_allowlist_additions = vec!["anything.example".to_string()];
        c.resource_limits = ResourceLimitsConfig {
            cpus: 1.0,
            memory_mb: 512,
        };
        c
    }] {
        let paths = SessionPaths::new("/tmp/habitat-config-invariants-network-state");
        let request = run::launch_request(
            SessionId::from_name("habitat-config-invariants-network-session").unwrap(),
            &paths,
            &config,
            "localhost/habitat-guest:alpine".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
            "ssh-ed25519 AAAAtest".to_string(),
            PathBuf::from("/tmp/habitat-config-invariants-network-key"),
        );
        let args = build_run_args(&request);
        let idx = args.iter().position(|a| a == "--network").expect("--network must always be present");
        assert!(
            args[idx + 1].starts_with(habitat_egress::network_setup::NETWORK_MODE),
            "--network must always be the fixed hardened pasta mode: {:?}",
            args[idx + 1]
        );
        assert_ne!(args[idx + 1], "host");
    }
}
