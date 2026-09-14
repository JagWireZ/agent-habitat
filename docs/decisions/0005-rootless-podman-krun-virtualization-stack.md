# 0005. Virtualization stack is rootless Podman + the krun runtime (libkrun), not containerd + Kata + Firecracker

Status: accepted
Date: 2026-09-14

Supersedes: `0001-linux-only-host-in-v1.md`

## Context

`0001-linux-only-host-in-v1.md` established that the host must be Linux
with hardware virtualization available, because the chosen VM engine
(Kata Containers + Firecracker, launched via containerd/nerdctl) required
KVM and ran its launcher with elevated host privileges -- "standard
practice for this kind of infrastructure," per the original
`docs/plan.md` Section 2.1, but still a second piece of host
infrastructure (containerd) and a privilege footprint broader than the
sandbox itself strictly needed.

Re-evaluating that stack surfaced a materially simpler option: Podman's
`krun` runtime, backed by libkrun, gives the same real-VM-boundary
guarantee (hardware-virtualization-backed isolation, not a shared kernel)
without either of those two costs. libkrun is a lightweight VMM library
purpose-built for exactly this "one microVM per container-shaped
workload" case, and Podman already runs fully rootless -- no daemon, no
socket, no elevated launcher process. On the two package families v1 and
v1.1 target (`0006-sequential-platform-roadmap.md`), it ships as a single
package (`crun-krun`) rather than a multi-binary manual install.

This is a newer, less battle-tested combination than the old one (see
`docs/plan.md` Known limitations) and doesn't yet have a well-trodden
public reference to follow end to end -- rootless Podman, `krun`,
block-device-backed storage, and `passt` networking (Section 2.3) all
have to be validated together, not assumed to compose cleanly because
each piece individually is known-good.

## Decision

Agent Habitat's containment boundary is rootless Podman launching each
session through the `krun` OCI runtime (package `crun-krun`, backed by
libkrun) -- not containerd/nerdctl driving Kata Containers + Firecracker.
Concretely:

- No containerd, no nerdctl, and no separate Firecracker binary are
  required or checked for. `habitat install` and `habitat run`'s
  preflight instead verify Podman (present, usable rootless -- `podman
  info` succeeds without a daemon) and the `krun` runtime (`crun-krun`
  runnable on PATH).
- The host-Linux-with-KVM requirement from `0001` stands unchanged in
  substance: libkrun still needs hardware virtualization, which is still
  a Linux kernel feature. What changes is that reaching it needs no
  elevated host privilege at all -- the only host-side prerequisite
  beyond the two packages above is the launching user's one-time
  membership in the `kvm` group, a permission grant, not a per-session
  elevation.
- Guest storage is a disposable raw disk image attached as a
  `virtio-blk` block device, mounted by the guest's own kernel -- no
  host-side loop-device or root-owned mountpoint step, keeping storage
  setup consistent with the rootless launch model.
- Guest networking is `passt`, not libkrun's default TSI (transparent
  socket impersonation) mode -- TSI proxies guest socket calls directly
  and isn't visible to normal host firewall rules, which would undermine
  the egress-restriction design in `docs/plan.md` Section 2.3. `passt`
  gives the guest a real virtual network interface that host-side
  network policy can actually see and restrict.

## Consequences

- `crates/install/src/checks.rs`'s four checks are: host OS, KVM, Podman,
  krun-runtime -- replacing the prior host OS, KVM, containerd/nerdctl,
  Kata/Firecracker set. This is a behavior-preserving rename in shape
  (still four fail-closed, individually-named checks) but a real change
  in what's actually verified.
- `docs/decisions/0004-ship-prebuilt-host-binaries.md`'s prerequisite list
  and packaging consequences need updating to match (tracked there, not
  duplicated here).
- No host-OS-detection branches, nested-VM workarounds, or "best effort"
  paths for macOS/Windows are introduced by this change -- `0001`'s
  consequences on that point are unaffected.
- The "verify before trusting" validation this newer combination needs
  (AGENTS.md Section 3) now covers rootless Podman + `krun` + block-device
  storage + `passt`, in place of containerd + Kata + Firecracker -- the
  Phase 8 validation run-book (`tmp/wip/implementation-plan.md`) is
  updated to reflect the new stack, not left describing the old one.
- DNS resolution inside the guest under `passt` is an explicit open item
  (`docs/plan.md` Section 2.3) that needs verification before v1 ships --
  a leftover default resolver would be a way for the network restriction
  to quietly leak.
