//! `habitat-install` -- installer and launch-time preflight checks.
//!
//! Phase 1 responsibility (see `tmp/wip/implementation-plan.md`):
//! - `habitat install`: detect/verify containerd + nerdctl, verify Kata
//!   Containers + Firecracker availability, refuse explicitly on non-Linux
//!   hosts (see `docs/decisions/0001-linux-only-host-in-v1.md`).
//! - `habitat run`'s preflight subroutine: real KVM/hardware-virtualization
//!   capability probe, containerd/Kata/Firecracker reachability check.
//!   Every check fails closed -- names the specific failed check, exits
//!   non-zero, logs to the audit destination tagged as a distinct
//!   preflight-failure event (AGENTS.md Section 2, invariant 11).
//!
//! No logic yet -- Phase 0 scaffolding only.
