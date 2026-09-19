//! `habitat-vm` -- the containment boundary: launch, lifecycle, teardown.
//!
//! - [`launcher`]: builds the `podman run` invocation that starts a
//!   session's microVM through the `krun` runtime, bind-mounting the
//!   `habitat-workspace`-built staging directory into the guest at
//!   `/workspace`. No elevated host privilege is required -- Podman runs
//!   as the calling user (with one-time `kvm` group membership); the
//!   security boundary is the VM/kernel isolation, not the launcher.
//! - [`session`]: the session identifier scheme ([`session::SessionId`])
//!   and the request/handle types the launcher operates on.
//! - [`launcher::teardown`]: workspace staging directory removed, VM
//!   container force-removed.
//! - Resource-limit enforcement (CPU/memory caps) is read from
//!   `habitat_policy::resource_limits` and applied in
//!   [`launcher::build_run_args`].
//! - The only bind mount ever passed to `podman run` is the disposable
//!   staging directory at `/workspace` -- never `project_root` itself,
//!   or any other arbitrary host path.
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
