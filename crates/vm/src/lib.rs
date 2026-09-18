//! `habitat-vm` -- the containment boundary: launch, lifecycle, teardown.
//!
//! - [`launcher`]: builds the `podman run` invocation that starts a
//!   session's microVM through the `krun` runtime against the
//!   `habitat-workspace`-built disk image, attached as a `virtio-blk`
//!   block device. No elevated host privilege is required -- Podman runs
//!   as the calling user (with one-time `kvm` group membership); the
//!   security boundary is the VM/kernel isolation, not the launcher.
//! - [`session`]: the session identifier scheme ([`session::SessionId`])
//!   and the request/handle types the launcher operates on.
//! - [`launcher::teardown`]: disk image deleted, VM container
//!   force-removed.
//! - Resource-limit enforcement (CPU/memory caps) is read from
//!   `habitat_policy::resource_limits` and applied in
//!   [`launcher::build_run_args`].
//! - No live/continuous file-share mount at any point -- the workspace
//!   disk crosses in exactly once, as a launch-time block-device attach.
//!
//! **Not covered here:** actually booting against real KVM --
//! `tests/manual/validate-vm-launch.sh` does that, since this dev
//! container and CI have no hardware virtualization.
//!
//! The launch command's `--network`/`--dns` flags come from
//! `habitat_egress::network_setup::build_network_flags` -- a real
//! `passt`-backed interface pinned to the session's egress proxy. This
//! crate only splices that module's output into its own argv; the
//! egress policy itself lives in `crates/egress`.
//!
//! [`guest_ssh`]: generates each session's ephemeral SSH keypair --
//! `podman exec` does not work against `krun`, so
//! `launcher::build_run_args` bakes the public key into the guest via an
//! env var, and `launcher::launch` resolves the guest's address so
//! `habitat-workspace`'s guest-exec channel can reach it.

pub mod command_runner;
pub mod guest_ssh;
pub mod launcher;
pub mod session;
