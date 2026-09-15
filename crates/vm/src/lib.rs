//! `habitat-vm` -- the containment boundary: launch, lifecycle, teardown.
//!
//! Phase 3 (see `tmp/wip/implementation-plan.md`):
//! - [`launcher`]: builds the `podman run` invocation that starts a
//!   session's microVM through the `krun` runtime (`crun-krun`, backed by
//!   libkrun) against the `habitat-workspace`-built disk image
//!   (`0003-container-engine-runtime-layer.md`), attached as a
//!   `virtio-blk` block device (`0005-storage-layer.md`). No elevated
//!   host privilege is required for this launch -- Podman runs entirely
//!   as the calling user, with one-time `kvm` group membership as the
//!   only host-side prerequisite; the security boundary is the
//!   VM/kernel isolation, not the launcher (`docs/plan.md` Section 2.1).
//! - [`session`]: the session identifier scheme
//!   ([`session::SessionId`]) and the request/handle types
//!   ([`session::LaunchRequest`], [`session::LaunchedSession`]) the
//!   launcher operates on.
//! - [`launcher::teardown`]: session teardown -- disk image deleted, VM
//!   container force-removed, nothing persisted beyond what already
//!   synced to host (Phase 4's job, not this crate's).
//! - Resource-limit enforcement (CPU/memory caps) is read from the
//!   shared config (`habitat_policy::resource_limits`) and applied as
//!   `podman run` flags in [`launcher::build_run_args`].
//! - No live/continuous file-share mount at any point (`AGENTS.md`
//!   Section 2, invariant 1) -- the workspace disk crosses in exactly
//!   once, as a launch-time block-device attach, never a bind mount.
//!
//! **What this crate does not (yet) cover:** actually booting against
//! real KVM and confirming a concrete escape attempt fails --
//! `tests/manual/validate-vm-launch.sh` is that verification, since
//! neither this dev container nor this project's CI has real hardware
//! virtualization available (`AGENTS.md` Section 3). Egress (Phase 5)
//! and the full audit trail (Phase 6) are later phases' responsibility;
//! this crate's `--network none` default is a placeholder Phase 5
//! replaces, not a finished egress story.

pub mod command_runner;
pub mod launcher;
pub mod session;
