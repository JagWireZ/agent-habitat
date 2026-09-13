# 0001. Host machine is Linux-only in v1

Status: accepted
Date: 2026-09-13

## Context

Agent Habitat's containment boundary is a real virtual machine (Kata
Containers + Firecracker), not a shared-kernel container. Firecracker
requires KVM on the host to provide that boundary. KVM is a Linux kernel
feature; it is not natively available on macOS or Windows.

A nested-VM workaround (e.g. running the whole stack inside Docker
Desktop's or WSL2's own Linux VM) is technically conceivable, but it adds
a second virtualization layer between the guest and the real host, changes
the performance and isolation characteristics the design relies on, and
has not been validated. Silently supporting it, or falling back to a
weaker containment mechanism on non-Linux hosts, would create a "best
effort" security posture that contradicts the project's single
hardened-setup principle (`docs/plan.md` Section 2.5).

## Decision

The host machine must be Linux, with hardware virtualization available,
for v1, v1.1 (Fedora guest), and v2 (Ubuntu guest). `habitat install` and
`habitat run`'s preflight check explicitly refuse on a non-Linux host or a
host without KVM exposed -- refusal is fail-closed and reported by name,
never silently degraded to a weaker mode and never assumed to work via an
untested nested-VM path.

## Consequences

- No host-OS-detection branches, nested-VM workarounds, or "best effort"
  code paths for macOS/Windows are to be built preemptively (AGENTS.md
  Section 1).
- macOS and Windows host support remains future work, explicitly not yet
  designed. Per AGENTS.md Section 4, it is deferred until Linux-host
  v1/v1.1/v2 have shipped and been validated, and until the host isolation
  model for a non-KVM host has actually been designed and reviewed -- not
  assumed to be "the same, but for another OS."
- The hardware-virtualization preflight check must be a real capability
  probe (e.g. `/dev/kvm` access and CPU flags), not an assumption, because
  it can be silently unavailable on some cloud VMs even when the host OS
  is Linux (`docs/plan.md` Known limitations).
