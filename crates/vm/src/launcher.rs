//! Builds and runs the `podman run` invocation that starts one session's
//! microVM against a Phase 2 disk image, and the corresponding teardown
//! invocation. Argv construction ([`build_run_args`]) is pure logic and
//! fully unit-tested here; actually booting against real KVM and
//! attempting an escape is Phase 3's `tests/manual` runbook's job -- this
//! dev container and this project's CI (`ubuntu-latest`, no nested
//! virtualization) have neither Podman+krun installed nor `/dev/kvm`
//! (`tmp/wip/implementation-plan.md`'s Phase 3 exit gate).
//!
//! **Real-hardware caveat, same shape as Phase 1's krun-runtime
//! package/binary-name lesson
//! (`docs/decisions/0003-container-engine-runtime-layer.md`):** the exact
//! OCI annotation crun-krun expects for attaching an extra `virtio-blk`
//! device ([`WORKSPACE_DISK_ANNOTATION`]) is this launcher's current best
//! understanding, not yet confirmed against real crun-krun on real
//! hardware. Confirming (and, if it differs, correcting) that annotation
//! key is explicitly part of Phase 3's real-hardware runbook
//! (`tests/manual/validate-vm-launch.sh`), not something to assume
//! correct by inspection (`AGENTS.md` Section 3).

use crate::command_runner::CommandRunner;
use crate::session::{LaunchRequest, LaunchedSession};
use std::fmt;

/// Path to the `krun` binary invoked as podman's `--runtime`. Not
/// `crun-krun` -- see `crates/install/src/checks.rs::krun_runtime`'s doc
/// comment for why the package and binary names differ; the same
/// distinction applies here.
pub const KRUN_RUNTIME: &str = "krun";

/// The OCI annotation key this launcher uses to tell crun-krun which
/// extra disk image to attach to the guest as a `virtio-blk` device,
/// alongside the guest's own root filesystem (`0005-storage-layer.md`).
/// See this module's doc comment for the real-hardware caveat on this
/// specific key.
pub const WORKSPACE_DISK_ANNOTATION: &str = "io.habitat.vm.workspace-disk";

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
/// no side effects, so command construction is fully testable without
/// Podman/krun/KVM actually present.
///
/// Deliberately absent from this argv, by construction: any `-v` or
/// `--mount type=bind` flag. The workspace disk crosses in exactly once,
/// via the `--annotation` below, resolved at launch -- never a live,
/// continuously-mounted share (`AGENTS.md` Section 2, invariant 1;
/// `0005-storage-layer.md`). Also absent: any host-privilege-widening
/// flag (`--privileged`, `--cap-add`, `--pid=host`, `--network=host`,
/// `--security-opt` loosening) -- the containment boundary is the VM
/// itself, not a hardened container config layered on top of it
/// (`0003-container-engine-runtime-layer.md`). `tests/adversarial/
/// containment_escape.rs` pins both of these absences as a mocked-seam
/// check; the real, booted escape-attempt is `tests/manual`'s job.
///
/// Networking (Phase 5): `habitat_egress::network_setup::
/// build_network_flags` supplies the `--network`/`--dns` flags -- a real
/// `passt`-backed interface pinned to the session's egress proxy, never
/// libkrun's default TSI mode (invisible to host firewall rules) and
/// never left unset (`docs/decisions/0004-networking-layer.md`). Actual
/// reachability restriction (making the proxy the *only* address the
/// guest can reach) is a separate nftables ruleset
/// (`habitat_egress::network_setup::build_egress_firewall_rules`)
/// applied alongside this launch, not a `podman run` flag itself.
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
    args.extend(habitat_egress::network_setup::build_network_flags(
        request.egress_proxy_addr,
    ));
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
        request.guest_image.clone(),
    ]);
    args
}

/// Launches one session: runs `podman run` (detached) with the argv from
/// [`build_run_args`] and returns a [`LaunchedSession`] handle. Fails
/// closed on anything but a clean, successful launch -- a non-zero exit
/// or an unstartable `podman` binary is `Err`, never a "probably fine"
/// partial success.
pub fn launch<R: CommandRunner>(
    request: &LaunchRequest,
    runner: &R,
) -> Result<LaunchedSession, LaunchError> {
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

    Ok(LaunchedSession {
        session_id: request.session_id.clone(),
        workspace_disk_path: request.workspace_disk_path.clone(),
    })
}

/// Tears a session down: force-removes the podman container (even though
/// `--rm` already asks podman to clean up on a normal stop, this covers a
/// hung/uncleanly-stopped guest too) and deletes the session's disk
/// image. Both steps are idempotent -- tearing down a session that's
/// already gone (container already removed, disk already deleted)
/// succeeds rather than erroring, matching this project's standing
/// idempotency bar (`AGENTS.md` Section 7 / Phase 1's
/// install-run-twice-makes-no-changes exit gate, applied here to
/// teardown instead of install).
///
/// Nothing is left behind that a later session could read: no residual
/// writable artifact reachable once this returns `Ok`
/// (`tmp/wip/implementation-plan.md`'s Phase 3 exit gate).
pub fn teardown<R: CommandRunner>(
    session: &LaunchedSession,
    runner: &R,
) -> Result<(), LaunchError> {
    // `--ignore` makes `podman rm` treat "no such container" as success
    // rather than an error -- teardown of an already-gone session must
    // not fail just because it's already gone.
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
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(err(format!(
            "could not remove disk image {}: {e}",
            session.workspace_disk_path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::testing::FakeCommandRunner;
    use crate::session::SessionId;
    use habitat_policy::resource_limits::ResourceLimitsConfig;
    use std::path::PathBuf;

    fn sample_request() -> LaunchRequest {
        LaunchRequest {
            session_id: SessionId::from_name("habitat-test-session").unwrap(),
            workspace_disk_path: PathBuf::from("/tmp/habitat-test-session.img"),
            guest_image: "localhost/habitat-guest:almalinux".to_string(),
            resource_limits: ResourceLimitsConfig {
                cpus: 2.0,
                memory_mb: 2048,
            },
            egress_proxy_addr: "127.0.0.1:8443".parse().unwrap(),
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
            Some(&"localhost/habitat-guest:almalinux".to_string())
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
        assert_eq!(args[net_idx + 1], "pasta");
        let dns_idx = args.iter().position(|a| a == "--dns").unwrap();
        assert_eq!(args[dns_idx + 1], "127.0.0.1");
    }

    #[test]
    fn build_run_args_attaches_the_workspace_disk_via_annotation() {
        let args = build_run_args(&sample_request());
        let ann_idx = args.iter().position(|a| a == "--annotation").unwrap();
        assert_eq!(
            args[ann_idx + 1],
            format!("{WORKSPACE_DISK_ANNOTATION}=/tmp/habitat-test-session.img")
        );
    }

    /// No live/continuous file-share mount at any point (`AGENTS.md`
    /// Section 2, invariant 1) -- pinned at the command-construction
    /// level here; `tests/adversarial/containment_escape.rs` covers the
    /// same absence plus the broader host-privilege-widening flags.
    #[test]
    fn build_run_args_never_includes_a_bind_mount_flag() {
        let args = build_run_args(&sample_request());
        assert!(!args.iter().any(|a| a == "-v" || a == "--volume"));
        assert!(!args
            .iter()
            .any(|a| a.starts_with("--mount") || a.contains("type=bind")));
    }

    #[test]
    fn launch_fails_closed_when_podman_exits_non_zero() {
        let request = sample_request();
        let args = build_run_args(&request);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let invocation = format!("podman {}", arg_refs.join(" "));
        let runner = FakeCommandRunner::default()
            .with_failure(&invocation, "error: no such runtime handler krun");

        let err = launch(&request, &runner).unwrap_err();
        assert!(err.message.contains("non-zero"));
    }

    #[test]
    fn launch_succeeds_when_podman_reports_success() {
        let request = sample_request();
        let args = build_run_args(&request);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let invocation = format!("podman {}", arg_refs.join(" "));
        let runner = FakeCommandRunner::default().with_ok(&invocation, "abc123containerid\n");

        let launched = launch(&request, &runner).unwrap();
        assert_eq!(launched.session_id, request.session_id);
    }

    #[test]
    fn launch_fails_closed_when_podman_is_not_on_path() {
        let request = sample_request();
        // Deliberately no invocation configured on the fake -- simulates
        // `podman` not being found at all.
        let runner = FakeCommandRunner::default();
        let err = launch(&request, &runner).unwrap_err();
        assert!(err.message.contains("PATH"));
    }

    #[test]
    fn teardown_removes_the_container_and_deletes_the_disk_image() {
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

        let session = crate::session::LaunchedSession {
            session_id: SessionId::from_name("habitat-teardown-session").unwrap(),
            workspace_disk_path: image_path.clone(),
        };
        let runner = FakeCommandRunner::default().with_ok(
            "podman rm --force --ignore habitat-teardown-session",
            "habitat-teardown-session\n",
        );

        teardown(&session, &runner).unwrap();
        assert!(
            !image_path.exists(),
            "the disk image must be deleted on teardown -- no residual artifact"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn teardown_is_idempotent_when_the_disk_image_is_already_gone() {
        let session = crate::session::LaunchedSession {
            session_id: SessionId::from_name("habitat-already-gone").unwrap(),
            workspace_disk_path: PathBuf::from("/tmp/habitat-already-gone-does-not-exist.img"),
        };
        let runner = FakeCommandRunner::default()
            .with_ok("podman rm --force --ignore habitat-already-gone", "");
        // A second teardown of the same (already torn-down) session must
        // still succeed, never error just because there's nothing left
        // to remove.
        assert!(teardown(&session, &runner).is_ok());
        assert!(teardown(&session, &runner).is_ok());
    }

    #[test]
    fn teardown_fails_closed_when_podman_rm_exits_non_zero_for_a_real_reason() {
        let session = crate::session::LaunchedSession {
            session_id: SessionId::from_name("habitat-stuck-session").unwrap(),
            workspace_disk_path: PathBuf::from("/tmp/habitat-stuck-session-does-not-exist.img"),
        };
        let runner = FakeCommandRunner::default().with_failure(
            "podman rm --force --ignore habitat-stuck-session",
            "error: unable to stop container: timed out",
        );
        let err = teardown(&session, &runner).unwrap_err();
        assert!(err.message.contains("non-zero"));
    }
}
