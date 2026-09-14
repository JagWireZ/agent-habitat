# 0002. Guest OS layer: guest image mirrors the current host roadmap stage, no separate guest-distro axis

Status: accepted
Date: 2026-09-14

## Context

The virtualization stack is rootless Podman + the `krun` runtime
(`0003-container-engine-runtime-layer.md`), which removes any reason to
keep the guest's platform choice distinct from the host's. A stack built
around containerd/Kata-style host-side tooling and a separately-selected
guest image would have a genuine reason to pick the guest independently
of host distro family (minimal attack surface and fast boot, regardless
of what the host happens to run). Under Podman + `krun`, there is no such
separate guest-image-selection axis: the guest is a minimal image built
for whichever platform `habitat` is itself validated against at the
current roadmap stage, and there is no benefit to picking a different
distro family for the two.

## Decision

The guest has no distro roadmap or per-project choice of its own. At each
stage of the host roadmap (`0001-host-os-layer.md`: AlmaLinux for v1,
Fedora for v1.1, Ubuntu for v2), the guest image is built from that same
platform. "AlmaLinux" / "Fedora" / "Ubuntu" each describes one platform
covering both what `habitat` runs on and what the guest image is built
from -- not two independently-chosen values that happen to coincide.

No guest-side code path should assume a fixed, permanent guest platform
independent of the host roadmap, and no distro-conditional guest code
paths for Fedora or Ubuntu belong in the codebase before their respective
roadmap stage starts.

## Consequences

- The disk-build pipeline (Phase 2), VM launch (Phase 3), and any
  guest-side assumptions baked into sync or egress tooling target
  AlmaLinux-specific package layout and tooling for v1, then move to
  Fedora's (v1.1) and Ubuntu's (v2) in step with the host roadmap -- they
  are not required to be distro-agnostic from day one, but they also
  don't get to assume a permanently fixed guest platform.
- Guest platform changes are never staged ahead of the host roadmap stage
  they belong to (AGENTS.md Section 5's build-order rules).
