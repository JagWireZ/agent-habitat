# 0001. Host OS layer: Linux-only host, sequential distro roadmap (AlmaLinux -> Fedora -> Ubuntu)

Status: accepted
Date: 2026-09-14

## Context

Two separate questions live at the host OS layer: what kind of host is
required at all, and which specific host distros are supported, in what
order.

**Requirement.** Agent Habitat's containment boundary is a real virtual
machine (rootless Podman + the `krun` runtime, backed by libkrun --
`0003-container-engine-runtime-layer.md`). libkrun needs hardware
virtualization (KVM), which is a Linux kernel feature not natively
available on macOS or Windows. A nested-VM workaround (e.g. running the
whole stack inside Docker Desktop's or WSL2's own Linux VM) is technically
conceivable, but it adds a second virtualization layer between the guest
and the real host, changes the performance and isolation characteristics
the design relies on, and has not been validated. Silently supporting it,
or falling back to a weaker containment mechanism on non-Linux hosts,
would create a "best effort" security posture that contradicts the
project's single hardened-setup principle (`docs/plan.md` Section 2.5).

**Sequencing.** `habitat install`'s installer/preflight logic is
package-manager-specific, and validating it against every possible Linux
host distro before v1 ships isn't practical. Validating multiple host
families (e.g. an rpm-based family and a deb-based family) together from
the start would multiply validation surface before the core system's
claims (real VM isolation, fail-closed preflight, blocklist-before-copy,
two-point sync, default-deny egress) have been shown to hold for even one
family. AlmaLinux and Fedora share the same package family (dnf/rpm) and
the same `crun-krun` packaging, making a first-then-next-family sequence
lower-risk than committing to two families in parallel.

## Decision

**Requirement:** The host machine must be Linux, with hardware
virtualization available, throughout the platform roadmap. `habitat
install` and `habitat run`'s preflight check explicitly refuse on a
non-Linux host or a host without KVM exposed -- a real capability probe
(e.g. `/dev/kvm` access and CPU flags), not an assumption, because it can
be silently unavailable on some cloud VMs even when the host OS is Linux
(`docs/plan.md` Known limitations). Refusal is fail-closed and reported by
name, never silently degraded to a weaker mode and never assumed to work
via an untested nested-VM path.

**Sequencing:** The host distro roadmap is a single sequential line, not
multiple families validated in parallel:

1. **v1 -- AlmaLinux.** The full system validated end-to-end on real
   hardware.
2. **v1.1 -- Fedora.** Expected to be a light lift given how closely it's
   related to AlmaLinux (same dnf/rpm family, same `crun-krun` packaging),
   but still requires its own validation pass, not an assumption of a free
   port.
3. **v2 -- Ubuntu.** A different security model under the hood (per
   `docs/plan.md` Section 5), so this waits until v1 is proven out rather
   than shipping in parallel with an rpm-based family.

No distro-conditional code paths for Fedora or Ubuntu belong in the
codebase before their respective roadmap stage starts, with one
exception: `habitat install`'s optional auto-install step. It offers to
run the actual package-manager install command once a check has already
failed, rather than only printing instructions, and doing that usefully
requires knowing which package manager it's talking to. **Amendment
(2026-09-14):** `habitat install` detects the host's package-manager
family (dnf/rpm -- AlmaLinux, Fedora, RHEL, Rocky, CentOS; apt/dpkg --
Debian, Ubuntu) via `/etc/os-release` and, on confirmation, runs `sudo
dnf install` or `sudo apt-get install` for whichever of Podman/crun-krun
is missing. This is narrower than "Fedora/Ubuntu support": it does not
change the sequential *validation* roadmap below -- v1 sign-off still
runs end-to-end against AlmaLinux alone, and a package that isn't
packaged for a family yet (`crun-krun` has no `.deb` until Ubuntu's v2
stage -- `0006-distribution-packaging-layer.md`) is reported as
unavailable there rather than guessed at. It only means the installer
itself can bootstrap prerequisites on a wider set of hosts than the
system as a whole is validated on.

## Consequences

- No host-OS-detection branches, nested-VM workarounds, or "best effort"
  code paths for macOS/Windows are to be built preemptively (AGENTS.md
  Section 1). The package-manager-family detection carved out above is
  narrowly scoped to `habitat install`'s auto-install step and does not
  reopen this for macOS/Windows or for other Linux families (Arch,
  openSUSE, etc.).
- macOS and Windows host support remains future work, explicitly not yet
  designed. Per AGENTS.md Section 4, it is deferred until the full
  sequential platform roadmap (v1 AlmaLinux, v1.1 Fedora, v2 Ubuntu) has
  shipped and been validated, and until the host isolation model for a
  non-KVM host has actually been designed and reviewed -- not assumed to
  be "the same, but for another OS."
- The hardware-virtualization preflight check must be a real capability
  probe, never an assumption.
- No parallel-family validation burden: Phase 8's validation run-book
  closes v1 sign-off against AlmaLinux alone; Fedora and Ubuntu validation
  happen at their own later roadmap stages, not as a precondition of v1
  shipping.
- Further host distro families (Arch, openSUSE) remain deferred per
  AGENTS.md Section 4's table, until v1.1 (Fedora) and v2 (Ubuntu) have
  both shipped and been validated end-to-end.
- `0006-distribution-packaging-layer.md`'s packaging cadence
  (`.rpm` for AlmaLinux/Fedora, `.deb` when Ubuntu starts) follows this
  sequence.
- The guest OS layer's platform is *not* tied to this roadmap: per
  `0002-guest-os-layer.md` (corrected 2026-09-15), the guest is a fixed
  Alpine image throughout every stage above -- an independent choice made
  once, not one that advances alongside AlmaLinux -> Fedora -> Ubuntu.
