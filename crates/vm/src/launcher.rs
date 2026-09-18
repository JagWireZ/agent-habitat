//! Builds and runs the `podman run` invocation that starts one session's
//! microVM against a Phase 2 disk image, and the corresponding teardown
//! invocation. Argv construction ([`build_run_args`]) is pure logic and
//! fully unit-tested here; actually booting against real KVM is
//! `tests/manual`'s job, since neither this dev container nor CI has
//! `/dev/kvm`.
//!
//! **Real-hardware caveat:** the OCI annotation crun-krun expects for
//! attaching the extra `virtio-blk` device ([`WORKSPACE_DISK_ANNOTATION`])
//! is this launcher's current best understanding, not yet confirmed
//! against real crun-krun (`tests/manual/validate-vm-launch.sh` covers
//! that).
//!
//! **Guest reachability under `pasta` is by published port, not guest
//! IP:** `podman inspect`'s `NetworkSettings` fields come back empty for
//! a `pasta`-backed container (`pasta` is a user-mode translator with no
//! Podman-tracked container-side IP), so reachability goes through an
//! explicit `--publish` port bound to `127.0.0.1` only, resolved after
//! launch via [`guest_ssh_port`].

use crate::command_runner::CommandRunner;
use crate::session::{LaunchRequest, LaunchedSession};
use habitat_audit::{AuditEvent, AuditSink, EventKind};
use std::fmt;

/// Path to the `krun` binary invoked as podman's `--runtime`. Not
/// `crun-krun` -- see `crates/install/src/checks.rs::krun_runtime` for
/// why the package and binary names differ.
pub const KRUN_RUNTIME: &str = "krun";

/// OCI annotation key telling crun-krun which extra disk image to attach
/// to the guest as a `virtio-blk` device. See this module's doc comment
/// for the real-hardware caveat on this key.
pub const WORKSPACE_DISK_ANNOTATION: &str = "io.habitat.vm.workspace-disk";

/// Env var carrying the guest's per-session authorized SSH public key
/// (`guest/entrypoint.sh` installs it into `~/.ssh/authorized_keys`).
/// Not a secret, so a plaintext env var is fine here.
pub const AUTHORIZED_KEY_ENV: &str = "HABITAT_AUTHORIZED_KEY";

/// The guest-side port `sshd` listens on -- not 22. Confirmed on real
/// hardware: `krun.use_passt=1` forwarding can't forward privileged
/// ports (<1024) into the guest at all (TCP handshake completes but the
/// connection resets on first data; upstream:
/// <https://github.com/containers/crun/issues/2251>). This channel is
/// loopback-only anyway, so there's no reason to fight for port 22.
const GUEST_SSH_PORT: u16 = 2222;

/// Host address the guest's SSH port is published to. Always loopback --
/// this exec channel must never be reachable from another machine.
pub const GUEST_SSH_HOST: &str = "127.0.0.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchError {
    pub message: String,
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vm launch: {}", self.message)
    }
}

impl std::error::Error for LaunchError {}

fn err(message: impl Into<String>) -> LaunchError {
    LaunchError {
        message: message.into(),
    }
}

/// Builds the argv for `podman run ...` from a [`LaunchRequest`] -- pure,
/// no side effects, fully testable without Podman/krun/KVM present.
///
/// Deliberately never includes: a `-v`/`--mount type=bind` flag (the
/// workspace disk crosses in exactly once, via the `--annotation`
/// below, never a live mounted share), or any host-privilege-widening
/// flag (`--privileged`, `--cap-add`, `--pid=host`, `--network=host`) --
/// the containment boundary is the VM itself. `tests/adversarial/
/// containment_escape.rs` pins both absences.
///
/// Networking: `habitat_egress::network_setup::build_network_flags`
/// supplies `--network`/`--dns`, a real `passt`-backed interface pinned
/// to the session's egress proxy (never libkrun's default TSI mode).
/// The reachability-restricting nftables ruleset
/// (`build_egress_firewall_rules`) is applied separately, not via a
/// `podman run` flag.
pub fn build_run_args(request: &LaunchRequest) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--detach".to_string(),
        "--rm".to_string(),
        "--name".to_string(),
        request.session_id.to_string(),
        "--runtime".to_string(),
        KRUN_RUNTIME.to_string(),
    ];
    args.extend(habitat_egress::network_setup::build_network_flags());
    args.extend([
        "--cpus".to_string(),
        format!("{}", request.resource_limits.cpus),
        "--memory".to_string(),
        format!("{}m", request.resource_limits.memory_mb),
        "--annotation".to_string(),
        format!(
            "{WORKSPACE_DISK_ANNOTATION}={}",
            request.workspace_disk_path.display()
        ),
        "--env".to_string(),
        format!("{AUTHORIZED_KEY_ENV}={}", request.guest_ssh_public_key),
        // Host port left unspecified (`::2222`) -- Podman assigns one,
        // resolved after launch by `guest_ssh_port`.
        "--publish".to_string(),
        format!("{GUEST_SSH_HOST}::{GUEST_SSH_PORT}/tcp"),
        request.guest_image.clone(),
    ]);
    args
}

/// Launches one session: runs `podman run` (detached), resolves the
/// guest's published SSH port ([`guest_ssh_port`]), and returns a
/// [`LaunchedSession`] handle. Fails closed on anything but a clean,
/// successful launch.
pub fn launch<R: CommandRunner>(
    request: &LaunchRequest,
    runner: &R,
    audit: &dyn AuditSink,
) -> Result<LaunchedSession, LaunchError> {
    // Marks the start of this session's lifecycle -- emitted for the
    // attempt itself, before we know whether `podman run` will succeed,
    // since an attempt is boundary-relevant on its own.
    let _ = audit.record(&AuditEvent::now(
        EventKind::SessionStart,
        None,
        format!(
            "launching session {} (guest image {})",
            request.session_id, request.guest_image
        ),
    ));

    let args = build_run_args(request);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let output = runner
        .run("podman", &arg_refs)
        .map_err(|e| err(format!("could not run `podman` (is it on PATH?): {e}")))?;

    if !output.status.success() {
        return Err(err(format!(
            "`podman run` exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let guest_ssh_port = guest_ssh_port(&request.session_id, runner)?;

    Ok(LaunchedSession {
        session_id: request.session_id.clone(),
        workspace_disk_path: request.workspace_disk_path.clone(),
        guest_ssh_host: GUEST_SSH_HOST.to_string(),
        guest_ssh_port,
        guest_ssh_private_key_path: request.guest_ssh_private_key_path.clone(),
    })
}

/// Resolves the host port a launched session's guest SSH port was
/// published to, via `podman port <name> <container-port>/tcp`. Expected
/// output is one line, `<host>:<port>` -- takes the substring after the
/// last `:` and parses it as a port number. Fails closed if `podman
/// port` fails or its output doesn't parse.
pub fn guest_ssh_port<R: CommandRunner>(
    session_id: &crate::session::SessionId,
    runner: &R,
) -> Result<u16, LaunchError> {
    let name = session_id.to_string();
    let container_port = format!("{GUEST_SSH_PORT}/tcp");
    let output = runner
        .run("podman", &["port", &name, &container_port])
        .map_err(|e| err(format!("could not run `podman port` (is it on PATH?): {e}")))?;
    if !output.status.success() {
        return Err(err(format!(
            "`podman port` exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let port_str = raw.rsplit(':').next().unwrap_or("");
    port_str.parse::<u16>().map_err(|_| {
        err(format!(
            "`podman port` output {raw:?} did not parse as \"host:port\" -- the pasta port-\
             publish setup may not have completed, or this command's output shape differs from \
             what this function expects (see this module's real-hardware caveat)"
        ))
    })
}

/// Tears a session down: force-removes the podman container (covers a
/// hung/uncleanly-stopped guest, beyond what `--rm` handles on a normal
/// stop), deletes the disk image, and deletes the ephemeral SSH keypair.
/// All three steps are idempotent -- tearing down an already-gone
/// session succeeds rather than erroring.
pub fn teardown<R: CommandRunner>(
    session: &LaunchedSession,
    runner: &R,
    audit: &dyn AuditSink,
) -> Result<(), LaunchError> {
    // `--ignore` makes `podman rm` treat "no such container" as success.
    let name = session.session_id.to_string();
    let output = runner
        .run("podman", &["rm", "--force", "--ignore", &name])
        .map_err(|e| err(format!("could not run `podman rm` (is it on PATH?): {e}")))?;

    if !output.status.success() {
        return Err(err(format!(
            "`podman rm --force --ignore {name}` exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    match std::fs::remove_file(&session.workspace_disk_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(err(format!(
                "could not remove disk image {}: {e}",
                session.workspace_disk_path.display()
            )))
        }
    }

    crate::guest_ssh::cleanup(&session.guest_ssh_private_key_path).map_err(|e| {
        err(format!(
            "could not remove session SSH key {}: {e}",
            session.guest_ssh_private_key_path.display()
        ))
    })?;

    let _ = audit.record(&AuditEvent::now(
        EventKind::SessionStop,
        None,
        format!("session {} torn down", session.session_id),
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::testing::FakeCommandRunner;
    use crate::session::SessionId;
    use habitat_audit::MemoryAuditSink;
    use habitat_policy::resource_limits::ResourceLimitsConfig;
    use std::path::PathBuf;

    fn sample_request() -> LaunchRequest {
        LaunchRequest {
            session_id: SessionId::from_name("habitat-test-session").unwrap(),
            workspace_disk_path: PathBuf::from("/tmp/habitat-test-session.img"),
            guest_image: "localhost/habitat-guest:alpine".to_string(),
            resource_limits: ResourceLimitsConfig {
                cpus: 2.0,
                memory_mb: 2048,
            },
            egress_proxy_addr: "127.0.0.1:8443".parse().unwrap(),
            guest_ssh_public_key: "ssh-ed25519 AAAAtest habitat-session".to_string(),
            guest_ssh_private_key_path: PathBuf::from("/tmp/habitat-test-session-key"),
        }
    }

    #[test]
    fn build_run_args_uses_the_krun_runtime_and_session_name() {
        let args = build_run_args(&sample_request());
        assert!(args.contains(&"--runtime".to_string()));
        assert!(args.contains(&KRUN_RUNTIME.to_string()));
        assert!(args.contains(&"--name".to_string()));
        assert!(args.contains(&"habitat-test-session".to_string()));
        assert_eq!(
            args.last(),
            Some(&"localhost/habitat-guest:alpine".to_string())
        );
    }

    #[test]
    fn build_run_args_reflects_resource_limits() {
        let mut request = sample_request();
        request.resource_limits = ResourceLimitsConfig {
            cpus: 4.0,
            memory_mb: 8192,
        };
        let args = build_run_args(&request);
        let cpus_idx = args.iter().position(|a| a == "--cpus").unwrap();
        assert_eq!(args[cpus_idx + 1], "4");
        let mem_idx = args.iter().position(|a| a == "--memory").unwrap();
        assert_eq!(args[mem_idx + 1], "8192m");
    }

    #[test]
    fn build_run_args_wires_the_egress_proxy_address_into_the_network_flags() {
        let mut request = sample_request();
        request.egress_proxy_addr = "127.0.0.1:9999".parse().unwrap();
        let args = build_run_args(&request);
        let net_idx = args.iter().position(|a| a == "--network").unwrap();
        assert_eq!(
            args[net_idx + 1],
            format!(
                "{}:--map-host-loopback={}",
                habitat_egress::network_setup::NETWORK_MODE,
                habitat_egress::network_setup::HOST_LOOPBACK_ADDR
            )
        );
        let dns_idx = args.iter().position(|a| a == "--dns").unwrap();
        assert_eq!(
            args[dns_idx + 1],
            habitat_egress::network_setup::HOST_LOOPBACK_ADDR
        );
    }

    /// Without this annotation, `crun-krun` silently falls back to
    /// libkrun's default TSI networking regardless of `--network pasta`,
    /// so it must always travel alongside `--network`/`--dns`.
    #[test]
    fn build_run_args_includes_the_krun_use_passt_annotation() {
        let args = build_run_args(&sample_request());
        let expected = format!(
            "{}=1",
            habitat_egress::network_setup::KRUN_USE_PASST_ANNOTATION
        );
        assert!(
            args.iter().any(|a| a == &expected),
            "expected {expected:?} somewhere in the argv, got {args:?}"
        );
    }

    #[test]
    fn build_run_args_attaches_the_workspace_disk_via_annotation() {
        let args = build_run_args(&sample_request());
        let expected_value = format!("{WORKSPACE_DISK_ANNOTATION}=/tmp/habitat-test-session.img");
        // There are two `--annotation` flags in the argv (build_network_flags
        // emits its own), so match on the value, not the first flag found.
        let ann_idx = args
            .iter()
            .position(|a| a == &expected_value)
            .expect("workspace-disk annotation value must be present");
        assert_eq!(args[ann_idx - 1], "--annotation");
    }

    #[test]
    fn build_run_args_never_includes_a_bind_mount_flag() {
        let args = build_run_args(&sample_request());
        assert!(!args.iter().any(|a| a == "-v" || a == "--volume"));
        assert!(!args
            .iter()
            .any(|a| a.starts_with("--mount") || a.contains("type=bind")));
    }

    #[test]
    fn build_run_args_bakes_the_authorized_key_in_as_an_env_var() {
        let args = build_run_args(&sample_request());
        let env_idx = args.iter().position(|a| a == "--env").unwrap();
        assert_eq!(
            args[env_idx + 1],
            format!("{AUTHORIZED_KEY_ENV}=ssh-ed25519 AAAAtest habitat-session")
        );
    }

    #[test]
    fn build_run_args_publishes_the_ssh_port_to_loopback_only() {
        let args = build_run_args(&sample_request());
        let pub_idx = args.iter().position(|a| a == "--publish").unwrap();
        assert_eq!(args[pub_idx + 1], "127.0.0.1::2222/tcp");
    }

    #[test]
    fn launch_fails_closed_when_podman_exits_non_zero() {
        let request = sample_request();
        let args = build_run_args(&request);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let invocation = format!("podman {}", arg_refs.join(" "));
        let runner = FakeCommandRunner::default()
            .with_failure(&invocation, "error: no such runtime handler krun");

        let audit = MemoryAuditSink::default();
        let err = launch(&request, &runner, &audit).unwrap_err();
        assert!(err.message.contains("non-zero"));
        // The attempt itself is still audited even though it failed.
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.tag(), "session-start");
    }

    fn port_invocation(session_name: &str) -> String {
        format!("podman port {session_name} {GUEST_SSH_PORT}/tcp")
    }

    #[test]
    fn launch_succeeds_and_resolves_the_guest_ssh_port_when_podman_reports_success() {
        let request = sample_request();
        let args = build_run_args(&request);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let invocation = format!("podman {}", arg_refs.join(" "));
        let runner = FakeCommandRunner::default()
            .with_ok(&invocation, "abc123containerid\n")
            .with_ok(
                &port_invocation("habitat-test-session"),
                "127.0.0.1:34567\n",
            );

        let audit = MemoryAuditSink::default();
        let launched = launch(&request, &runner, &audit).unwrap();
        assert_eq!(launched.session_id, request.session_id);
        assert_eq!(launched.guest_ssh_host, GUEST_SSH_HOST);
        assert_eq!(launched.guest_ssh_port, 34567);
        assert_eq!(
            launched.guest_ssh_private_key_path,
            request.guest_ssh_private_key_path
        );
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.tag(), "session-start");
    }

    #[test]
    fn launch_fails_closed_when_the_guest_ssh_port_cannot_be_resolved() {
        let request = sample_request();
        let args = build_run_args(&request);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let invocation = format!("podman {}", arg_refs.join(" "));
        let runner = FakeCommandRunner::default()
            .with_ok(&invocation, "abc123containerid\n")
            .with_ok(&port_invocation("habitat-test-session"), "");

        let audit = MemoryAuditSink::default();
        let err = launch(&request, &runner, &audit).unwrap_err();
        assert!(err.message.contains("did not parse"));
    }

    #[test]
    fn launch_fails_closed_when_podman_is_not_on_path() {
        let request = sample_request();
        let runner = FakeCommandRunner::default();
        let audit = MemoryAuditSink::default();
        let err = launch(&request, &runner, &audit).unwrap_err();
        assert!(err.message.contains("PATH"));
    }

    fn sample_session(image_path: PathBuf, key_path: PathBuf) -> crate::session::LaunchedSession {
        crate::session::LaunchedSession {
            session_id: SessionId::from_name("habitat-teardown-session").unwrap(),
            workspace_disk_path: image_path,
            guest_ssh_host: GUEST_SSH_HOST.to_string(),
            guest_ssh_port: 34567,
            guest_ssh_private_key_path: key_path,
        }
    }

    #[test]
    fn teardown_removes_the_container_disk_image_and_ssh_key() {
        let dir = std::env::temp_dir().join(format!(
            "habitat-vm-teardown-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let image_path = dir.join("session.img");
        std::fs::write(&image_path, b"pretend disk image contents").unwrap();
        let key_path = dir.join("session-key");
        std::fs::write(&key_path, b"pretend private key").unwrap();
        std::fs::write(dir.join("session-key.pub"), b"pretend public key").unwrap();

        let session = sample_session(image_path.clone(), key_path.clone());
        let runner = FakeCommandRunner::default().with_ok(
            "podman rm --force --ignore habitat-teardown-session",
            "habitat-teardown-session\n",
        );

        let audit = MemoryAuditSink::default();
        teardown(&session, &runner, &audit).unwrap();
        assert!(
            !image_path.exists(),
            "the disk image must be deleted on teardown -- no residual artifact"
        );
        assert!(
            !key_path.exists() && !dir.join("session-key.pub").exists(),
            "the session's SSH key must be deleted on teardown -- no residual credential"
        );
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.tag(), "session-stop");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn teardown_is_idempotent_when_the_disk_image_and_key_are_already_gone() {
        let session = sample_session(
            PathBuf::from("/tmp/habitat-already-gone-does-not-exist.img"),
            PathBuf::from("/tmp/habitat-already-gone-does-not-exist-key"),
        );
        let runner = FakeCommandRunner::default()
            .with_ok("podman rm --force --ignore habitat-teardown-session", "");
        let audit = MemoryAuditSink::default();
        assert!(teardown(&session, &runner, &audit).is_ok());
        assert!(teardown(&session, &runner, &audit).is_ok());
    }

    #[test]
    fn teardown_fails_closed_when_podman_rm_exits_non_zero_for_a_real_reason() {
        let session = sample_session(
            PathBuf::from("/tmp/habitat-stuck-session-does-not-exist.img"),
            PathBuf::from("/tmp/habitat-stuck-session-does-not-exist-key"),
        );
        let runner = FakeCommandRunner::default().with_failure(
            "podman rm --force --ignore habitat-teardown-session",
            "error: unable to stop container: timed out",
        );
        let audit = MemoryAuditSink::default();
        let err = teardown(&session, &runner, &audit).unwrap_err();
        assert!(err.message.contains("non-zero"));
    }
}
