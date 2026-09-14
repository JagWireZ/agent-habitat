//! `habitat-vm` -- the containment boundary: launch, lifecycle, teardown.
//!
//! Phase 3 responsibility (see `tmp/wip/implementation-plan.md`):
//! - Invoke rootless Podman with the `krun` runtime (`crun-krun`, backed by
//!   libkrun) to start a microVM against the `habitat-workspace`-built disk
//!   image. No elevated host privilege is required for this launch --
//!   Podman runs entirely as the calling user, with one-time `kvm` group
//!   membership as the only host-side prerequisite; the security boundary
//!   is the VM/kernel isolation, not the launcher (`docs/plan.md`
//!   Section 2.1).
//! - Session lifecycle primitives: start, teardown (disk + VM destroyed,
//!   nothing persisted beyond what already synced to host), a session
//!   identifier scheme for later audit/log phases.
//! - Resource-limit enforcement (CPU/memory/disk caps) read from the
//!   shared config (see `habitat-policy`).
//! - No live/continuous file-share mount at any point (AGENTS.md Section 2,
//!   invariant 1).
//!
//! No logic yet -- Phase 0 scaffolding only.
