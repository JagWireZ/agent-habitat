//! Adversarial coverage of `build_run_args`: confirms the launch argv never
//! grants a route back to the host (bind mounts, widened privileges,
//! disabled egress control). Real escape/KVM testing is
//! `tests/manual/validate-vm-launch.sh`'s job -- this only checks the argv
//! construction, not an actually-booted guest.

use habitat_egress::network_setup;
use habitat_policy::resource_limits::ResourceLimitsConfig;
use habitat_vm::launcher::build_run_args;
use habitat_vm::session::{LaunchRequest, SessionId};
use std::path::PathBuf;

fn sample_request() -> LaunchRequest {
    LaunchRequest {
        session_id: SessionId::from_name("habitat-adversarial-session").unwrap(),
        workspace_host_dir: PathBuf::from("/tmp/habitat-adversarial-session-workspace"),
        guest_image: "localhost/habitat-guest:alpine".to_string(),
        resource_limits: ResourceLimitsConfig::default(),
        egress_proxy_addr: "127.0.0.1:8443".parse().unwrap(),
        guest_ssh_public_key: "ssh-ed25519 AAAAtest habitat-session".to_string(),
        guest_ssh_private_key_path: PathBuf::from("/tmp/habitat-adversarial-session-key"),
    }
}

/// Exactly one bind mount may ever appear in the launch argv (`AGENTS.md`
/// Section 2, invariant 1) -- the disposable workspace staging directory,
/// via `-v`, never a `--mount type=bind` flag.
#[test]
fn launch_command_bind_mounts_exactly_once_via_dash_v() {
    let args = build_run_args(&sample_request());
    let v_count = args.iter().filter(|a| a.as_str() == "-v").count();
    assert_eq!(
        v_count, 1,
        "expected exactly one -v bind-mount flag, got {v_count}: {args:?}"
    );
    assert!(
        !args.iter().any(|a| a == "--volume"),
        "expected the short -v form, not --volume: {args:?}"
    );
    assert!(
        !args
            .iter()
            .any(|a| a.starts_with("--mount") || a.contains("type=bind")),
        "a --mount type=bind flag would be a second, redundant bind-mount mechanism: {args:?}"
    );
}

/// The only bind-mount source ever passed to `podman run` is the session's
/// disposable workspace staging directory -- never `project_root` or any
/// other arbitrary host path (`AGENTS.md` Section 2, invariant 1). A
/// regression that widens the bind-mount source must fail this test
/// clearly, rather than just changing what the flag-shape test above
/// happens to assert.
#[test]
fn launch_command_bind_mounts_only_the_expected_workspace_staging_dir() {
    let request = sample_request();
    let args = build_run_args(&request);
    let v_idx = args
        .iter()
        .position(|a| a == "-v")
        .expect("-v must be present");
    let mapping = &args[v_idx + 1];
    let expected_source = request.workspace_host_dir.display().to_string();
    assert!(
        mapping.starts_with(&format!("{expected_source}:")),
        "the only bind-mount source must be the session's workspace staging directory, got \
         {mapping:?}"
    );
    assert!(
        args.iter().filter(|a| a.as_str() == "-v").count() == 1,
        "a second -v flag could smuggle in a bind mount of an arbitrary host path: {args:?}"
    );
}

/// Containment is the VM/kernel boundary (`0003-container-engine-runtime-layer.md`),
/// never a widened container privilege -- no flag may hand the guest a
/// route to the host (privileged mode, added caps, host namespaces, or
/// unconfined seccomp).
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

/// The guest network must always be explicit `pasta` (`0004-networking-layer.md`)
/// -- never left unset (some Podman defaults reach the host's own netns
/// unfiltered) and never libkrun's default TSI mode, which host-side
/// firewall rules can't see at all.
#[test]
fn launch_command_always_uses_the_passt_backed_network_not_unset_or_tsi() {
    let args = build_run_args(&sample_request());
    let net_idx = args
        .iter()
        .position(|a| a == "--network")
        .expect("--network must be explicitly set, not left to podman's default");
    assert_eq!(
        args[net_idx + 1],
        format!(
            "{}:--map-host-loopback={}",
            network_setup::NETWORK_MODE,
            network_setup::HOST_LOOPBACK_ADDR
        )
    );
    // Real hardware: `--network pasta` alone isn't sufficient for
    // crun-krun -- without this annotation it silently falls back to TSI.
    let expected_annotation = format!("{}=1", network_setup::KRUN_USE_PASST_ANNOTATION);
    assert!(
        args.iter().any(|a| a == &expected_annotation),
        "expected {expected_annotation:?} somewhere in the argv, got {args:?}"
    );
}

/// DNS must point at [`network_setup::HOST_LOOPBACK_ADDR`], not the proxy's
/// own bind address directly -- `127.0.0.1` from inside the guest means its
/// *own* netns, not the host's; `pasta`'s `--map-host-loopback` is what
/// actually bridges guest DNS traffic to the host.
#[test]
fn launch_command_pins_guest_dns_to_the_egress_proxy() {
    let request = sample_request();
    let args = build_run_args(&request);
    let dns_idx = args
        .iter()
        .position(|a| a == "--dns")
        .expect("--dns must be explicitly set to the egress proxy's address");
    assert_eq!(args[dns_idx + 1], network_setup::HOST_LOOPBACK_ADDR);
}

/// The shared guest image reference and the per-session workspace
/// staging directory must never be conflated into the same argument.
#[test]
fn workspace_host_dir_and_guest_image_are_passed_as_distinct_arguments() {
    let request = sample_request();
    let args = build_run_args(&request);
    assert_eq!(
        args.last(),
        Some(&request.guest_image),
        "the guest image reference must be the final positional argument"
    );
    assert!(
        args.iter()
            .any(|a| a.contains(&request.workspace_host_dir.display().to_string())),
        "the workspace staging directory must appear (via the -v bind mount), separately from \
         the image ref"
    );
}

/// Only the public half of the SSH keypair may reach the guest via
/// `AUTHORIZED_KEY_ENV` -- checked by scanning for the PEM marker that
/// only a private key's OpenSSH encoding would contain.
#[test]
fn launch_command_never_leaks_a_private_key_shaped_value_into_the_env() {
    let mut request = sample_request();
    request.guest_ssh_public_key = "ssh-ed25519 AAAAtest habitat-session".to_string();
    let args = build_run_args(&request);
    let joined = args.join(" ");
    assert!(
        !joined.contains("PRIVATE KEY"),
        "no private-key-shaped value may ever appear in the launch argv: {args:?}"
    );
}

/// The guest's SSH port must be published to loopback only, never left
/// unspecified (some Podman defaults expose it on every host interface).
#[test]
fn launch_command_publishes_the_ssh_port_to_loopback_only_never_all_interfaces() {
    let args = build_run_args(&sample_request());
    let pub_idx = args
        .iter()
        .position(|a| a == "--publish")
        .expect("--publish must be explicitly set for the guest exec channel");
    let mapping = &args[pub_idx + 1];
    assert!(
        mapping.starts_with("127.0.0.1:"),
        "the SSH port publish must bind loopback only, got {mapping:?}"
    );
    assert!(
        !mapping.starts_with("0.0.0.0") && !mapping.starts_with(':'),
        "the SSH port publish must never bind all interfaces or Podman's unspecified default: {mapping:?}"
    );
}
