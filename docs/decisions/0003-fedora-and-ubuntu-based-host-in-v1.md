# 0003. Host OS family is Fedora-based and Ubuntu-based, in parallel, in v1

Status: superseded by 0006
Date: 2026-09-13

> Superseded 2026-09-14: the host/guest split this decision rested on (a
> fixed, separate minimal-Alpine guest, independent of host distro family)
> no longer applies once the virtualization stack moved to rootless
> Podman + the `krun` runtime
> (`0005-rootless-podman-krun-virtualization-stack.md`), which removes the
> reason to keep host and guest platform choices distinct. The roadmap is
> now a single sequential line -- AlmaLinux, then Fedora, then Ubuntu --
> instead of two host families validated together with a permanently
> fixed guest. See `0006-sequential-platform-roadmap.md` for the current
> decision. Kept here, unmodified below, as the historical record of the
> decision it replaces.

## Context

`0001-linux-only-host-in-v1.md` established that the host machine (the
one running `habitat`, not the guest inside the sandbox) must be Linux
with KVM available -- Firecracker's hard requirement. That decision left
"which Linux" open: in principle, any Linux distro with a working
KVM/containerd/Kata stack could work.

`0002-almalinux-only-guest-in-v1.md` had attempted to scope this further,
but mislabeled the scope as the **guest** distro -- the OS running inside
the sandbox VM. That was wrong on its face: the guest is a fixed, minimal
Alpine Linux image (`docs/plan.md` Section 2.1), chosen specifically for
its small attack surface and fast boot, and was never intended to have a
distro roadmap or a per-project choice at all. The AlmaLinux/Fedora/Ubuntu
roadmap 0002 described was always about the **host** -- the operator's
machine -- not the guest.

Separately from that mislabeling, the actual host-scoping question still
needs an answer: `habitat install`'s installer logic (detecting/verifying
containerd, nerdctl, Kata, Firecracker) is package-manager-specific, and
validating it against every possible Linux host distro before v1 ships
isn't practical. Fedora-based (dnf/rpm) and Ubuntu-based (apt/deb) hosts
together cover the large majority of real-world Linux systems operators
are likely to run `habitat` from.

## Decision

v1's host OS support targets exactly two distro families, built and
validated together, not one after the other:

- **Fedora-based** (dnf/rpm) hosts.
- **Ubuntu-based** (apt/deb) hosts.

Both ship together in v1 -- there is no "Fedora-based first, add
Ubuntu-based later" staging. `habitat install`'s package-manager-specific
logic (Phase 1) is built and validated against both from the start.

This decision is about the **host** only. The guest remains exactly as
`docs/plan.md` Section 2.1 describes it: a fixed, minimal Alpine Linux
image, with no distro roadmap, no per-project choice, and no interaction
with this decision.

## Consequences

- **Doubles host-family validation surface before v1 ships.** Phase 1's
  installer/preflight logic, and Phase 8's overall validation run-book,
  must each cover both host families, not one, before v1 sign-off.
- **No sequential fallback for the host.** Unlike a staged rollout, both
  host families are required for the v1 exit gate to close.
- **Further host distro families stay deferred.** A different Linux
  distro family (e.g. Arch, openSUSE) is out of scope until both v1 host
  lines (Fedora-based, Ubuntu-based) have shipped and been validated
  end-to-end -- see AGENTS.md Section 4's deferred-items table.
- **The guest is unaffected.** Nothing about the guest's distro, image
  build, or validation changes because of this decision -- it stays fixed
  at minimal Alpine, as it always was meant to.
- Supersedes `0002-almalinux-only-guest-in-v1.md`, which mislabeled this
  same underlying host-scoping question as a guest-scoping one.
