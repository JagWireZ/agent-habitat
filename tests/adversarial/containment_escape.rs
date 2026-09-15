//! Phase 3's adversarial coverage of the launch command itself -- the
//! part of "a concrete escape attempt fails" that can actually be checked
//! without real KVM: that the `podman run` argv this crate builds never
//! requests a host-reachable path in the first place. A booted guest that
//! never gets a bind mount, a host device, or a widened capability set
//! has nothing to escape *through* on that particular route, regardless
//! of what happens inside the guest -- which is exactly the part of this
//! phase's containment story that mocked-seam tests over pure argv
//! construction can meaningfully pin down.
//!
//! This deliberately does **not** claim to be the exit gate's real
//! escape-attempt test -- reaching host files, host processes, or the
//! host network namespace from *inside* an actually-booted guest needs
//! real KVM, which neither this dev container nor this project's CI has.
//! That real attempt is `tests/manual/validate-vm-launch.sh`'s job (see
//! `tests/manual/README.md` and `file-structure.md`, which puts Phase 3's
//! containment tests and Phase 5's egress-bypass tests together here and
//! in `tests/manual/`).

use habitat_policy::resource_limits::ResourceLimitsConfig;
use habitat_vm::launcher::build_run_args;
use habitat_vm::session::{LaunchRequest, SessionId};
use std::path::PathBuf;

fn sample_request() -> LaunchRequest {
    LaunchRequest {
        session_id: SessionId::from_name("habitat-adversarial-session").unwrap(),
        workspace_disk_path: PathBuf::from("/tmp/habitat-adversarial-session.img"),
        guest_image: "localhost/habitat-guest:almalinux".to_string(),
        resource_limits: ResourceLimitsConfig::default(),
        egress_proxy_addr: "127.0.0.1:8443".parse().unwrap(),
    }
}

/// No live/continuous file-share mount at any point (`AGENTS.md` Section
/// 2, invariant 1) -- a `-v`/`--volume`/`--mount type=bind` flag would be
/// exactly that kind of route back to the real host filesystem, and the
/// workspace disk crosses in exactly once via the block-device
/// annotation, never a bind mount.
#[test]
fn launch_command_never_bind_mounts_the_host_filesystem() {
    let args = build_run_args(&sample_request());
    assert!(
        !args.iter().any(|a| a == "-v" || a == "--volume"),
        "a -v/--volume flag would be a host filesystem bind mount: {args:?}"
    );
    assert!(
        !args
            .iter()
            .any(|a| a.starts_with("--mount") || a.contains("type=bind")),
        "a --mount type=bind flag would be a host filesystem bind mount: {args:?}"
    );
}

/// The security boundary is the VM/kernel isolation itself
/// (`0003-container-engine-runtime-layer.md`), never a widened
/// container-level privilege on top of it -- so none of the flags that
/// would hand a guest a route to the host (privileged mode, added
/// capabilities, the host PID/network/IPC namespaces, or a loosened
/// security policy) may ever appear in the launch argv.
#[test]
fn launch_command_never_widens_host_privilege() {
    let args = build_run_args(&sample_request());
    let joined = args.join(" ");
    let forbidden = [
        "--privileged",
        "--cap-add",
        "--pid=host",
        "--pid host",
        "--ipc=host",
        "--ipc host",
        "--network=host",
        "--userns=host",
        "--security-opt=seccomp=unconfined",
        "--security-opt seccomp=unconfined",
    ];
    for flag in forbidden {
        assert!(
            !joined.contains(flag),
            "launch argv must never include {flag:?} -- containment is the VM boundary, not a \
             container hardening layer: {args:?}"
        );
    }
}

/// The guest's network is always explicitly `pasta` (Phase 5's real
/// `passt`-backed egress path, `docs/decisions/0004-networking-layer.md`)
/// -- never left unset, which on some Podman defaults would mean an
/// unfiltered bridge network reaching the host's own network namespace,
/// and never libkrun's default TSI mode, which isn't visible to
/// host-side firewall rules at all. Fail closed on missing egress
/// control, never open by default.
#[test]
fn launch_command_always_uses_the_passt_backed_network_not_unset_or_tsi() {
    let args = build_run_args(&sample_request());
    let net_idx = args
        .iter()
        .position(|a| a == "--network")
        .expect("--network must be explicitly set, not left to podman's default");
    assert_eq!(args[net_idx + 1], "pasta");
}

/// DNS pinning (`0004`'s open item): the guest's resolver must be
/// pointed at the egress proxy, never left on whatever `pasta` would
/// otherwise hand it -- a leftover default resolver would be a way to
/// quietly leak past the reachability restriction.
#[test]
fn launch_command_pins_guest_dns_to_the_egress_proxy() {
    let request = sample_request();
    let args = build_run_args(&request);
    let dns_idx = args
        .iter()
        .position(|a| a == "--dns")
        .expect("--dns must be explicitly set to the egress proxy's address");
    assert_eq!(
        args[dns_idx + 1],
        request.egress_proxy_addr.ip().to_string()
    );
}

/// Every session gets its own disposable disk image, attached only via
/// the annotation this launcher controls -- confirms the guest image
/// reference (the shared, roadmap-stage-wide base image,
/// `0002-guest-os-layer.md`) and the per-session workspace disk
/// (`0005-storage-layer.md`) are never conflated into the same argument.
#[test]
fn workspace_disk_and_guest_image_are_passed_as_distinct_arguments() {
    let request = sample_request();
    let args = build_run_args(&request);
    assert_eq!(
        args.last(),
        Some(&request.guest_image),
        "the guest image reference must be the final positional argument"
    );
    assert!(
        args.iter()
            .any(|a| a.contains(&request.workspace_disk_path.display().to_string())),
        "the workspace disk path must appear (via the annotation), separately from the image ref"
    );
}
