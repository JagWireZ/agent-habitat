# 0003. Container engine/runtime layer: rootless Podman + the krun runtime (libkrun), not containerd + Kata + Firecracker

Status: accepted
Date: 2026-09-14

## Context

An earlier design ran each session through Kata Containers + Firecracker,
launched via containerd/nerdctl. Firecracker's containment guarantee
(hardware-virtualization-backed isolation, not a shared kernel) was
sound, but reaching it meant trusting a second piece of host
infrastructure (containerd) and running a launcher with elevated host
privileges -- a privilege footprint broader than the sandbox itself
strictly needed.

Podman's `krun` runtime, backed by libkrun, gives the same
real-VM-boundary guarantee without either of those two costs. libkrun is
a lightweight VMM library purpose-built for exactly this "one microVM per
container-shaped workload" case, and Podman already runs fully rootless
-- no daemon, no socket, no elevated launcher process. On the package
families v1 and v1.1 target (`0001-host-os-layer.md`), it ships as a
single package (`crun-krun`) rather than a multi-binary manual install.

This is a newer, less battle-tested combination than containerd + Kata +
Firecracker (see `docs/plan.md` Known limitations) and doesn't yet have a
well-trodden public reference to follow end to end -- it has to be
validated on its own merits, not assumed to compose cleanly because each
piece individually is known-good.

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
- Nothing about launching a session requires root or any other elevated
  host privilege. The only host-side prerequisite beyond the two packages
  above is the launching user's one-time membership in the `kvm` group, a
  permission grant, not a per-session elevation.

## Consequences

- `crates/install/src/checks.rs`'s four checks are: host OS, KVM, Podman,
  krun-runtime -- all four fail-closed and individually named.
- `0006-distribution-packaging-layer.md`'s prerequisite list and
  packaging consequences depend on this runtime choice.
- No host-OS-detection branches, nested-VM workarounds, or "best effort"
  paths for macOS/Windows are introduced by this change --
  `0001-host-os-layer.md`'s consequences on that point are unaffected.
- The "verify before trusting" validation this newer runtime needs
  (AGENTS.md Section 3) covers rootless Podman + `krun` -- the Phase 8
  validation run-book (`tmp/wip/implementation-plan.md`) reflects this
  runtime.
