# 0006. Platform roadmap is a single sequential line -- AlmaLinux, then Fedora, then Ubuntu

Status: accepted
Date: 2026-09-14

Supersedes: `0003-fedora-and-ubuntu-based-host-in-v1.md`

## Context

`0003-fedora-and-ubuntu-based-host-in-v1.md` scoped v1 to two host distro
families built and validated together (Fedora-based and Ubuntu-based),
with the guest fixed separately and permanently at a minimal Alpine
image with no roadmap of its own. That decision was itself a correction
of `0002-almalinux-only-guest-in-v1.md`, which had proposed an
AlmaLinux/Fedora/Ubuntu sequence but mislabeled it as a guest-scoping
decision.

Moving the virtualization stack to rootless Podman + the `krun` runtime
(`0005-rootless-podman-krun-virtualization-stack.md`) removes the reason
the host/guest split existed in the first place. The old stack needed a
guest image chosen purely for minimal attack surface and fast boot
(Alpine), independent of whatever distro family the host happened to be,
because containerd/Kata's host-side tooling and the guest's own image
were genuinely unrelated concerns. Under Podman + `krun`, there is no
separate guest-image-selection axis to keep distinct from the host: the
guest is a minimal image built for whichever platform `habitat` is
itself validated against, and there is no benefit to picking a different
distro family for the two. Keeping the host/guest split at this point
would preserve complexity the new stack doesn't require.

Separately, validating `habitat install`'s package-manager-specific logic
against two distro families in parallel from day one (as `0003` required)
multiplies validation surface before the core system's claims (real VM
isolation, fail-closed preflight, blocklist-before-copy, two-point sync,
default-deny egress) have been shown to hold for even one. AlmaLinux and
Fedora share the same package family (dnf/rpm) and the same `crun-krun`
packaging, making a first-then-next-family sequence a lower-risk path to
validating the core system than committing to two families in parallel.

## Decision

The platform roadmap is one sequential line, not a host-family-parallel /
guest-fixed split:

1. **v1 -- AlmaLinux.** The full system validated end-to-end on real
   hardware against AlmaLinux as the single target platform.
2. **v1.1 -- Fedora.** Expected to be a light lift given how closely it's
   related to AlmaLinux (same dnf/rpm family, same `crun-krun`
   packaging), but still requires its own validation pass, not an
   assumption of a free port.
3. **v2 -- Ubuntu.** A different security model under the hood (per
   `docs/plan.md` Section 5), so this waits until v1 is proven out rather
   than shipping in parallel with an rpm-based family.

There is no separate guest-distro axis: "AlmaLinux" / "Fedora" / "Ubuntu"
above describes the one platform each roadmap stage is validated
against, covering both what `habitat` runs on and what the guest image
is built from. No distro-conditional code paths for Fedora or Ubuntu
belong in the codebase before their respective roadmap stage starts.

## Consequences

- `docs/decisions/0002-almalinux-only-guest-in-v1.md` and
  `0003-fedora-and-ubuntu-based-host-in-v1.md` remain in place as the
  historical record of the decisions they replace -- not edited, not
  deleted -- but neither describes the current roadmap. This ADR is the
  current source of truth for platform sequencing.
- `docs/decisions/0004-ship-prebuilt-host-binaries.md`'s packaging
  cadence follows this sequence: `.rpm` packages for v1 (AlmaLinux) and
  v1.1 (Fedora), `.deb` packaging taken up when v2 (Ubuntu) starts --
  not both families built together as `0003` had required.
- **No parallel-family validation burden.** Phase 8's validation run-book
  (`tmp/wip/implementation-plan.md`) closes v1 sign-off against AlmaLinux
  alone; Fedora and Ubuntu validation happen at their own later roadmap
  stages, not as a precondition of v1 shipping.
- AGENTS.md Sections 1 and 5 (roadmap and build-order rules) need to
  describe this sequential line, replacing the "two host families in
  parallel, guest fixed separately" framing.
- Further platforms (Arch, openSUSE, macOS, Windows) remain deferred per
  AGENTS.md Section 4, unchanged by this decision except that the
  trigger is now "v1.1 (Fedora) and v2 (Ubuntu) have shipped," not "both
  v1 host families."
