# 0002. Guest OS layer: fixed Alpine guest, independent of the host roadmap

Status: accepted
Date: 2026-09-14
Corrected: 2026-09-15 (see "Correction" below -- the guest-platform
decision itself changed; the container-engine reasoning that motivated
looking at this layer at all did not)

## Context

The virtualization stack is rootless Podman + the `krun` runtime
(`0003-container-engine-runtime-layer.md`), which removes any reason to
pick the guest's platform *for compatibility reasons tied to the host*.
A stack built around containerd/Kata-style host-side tooling would have a
narrower, host-shaped guest-image story forced on it; under Podman +
`krun`, the guest image is just whatever OCI image `krun` boots, with no
host-distro-compatibility constraint on that choice at all.

That absence of a constraint is exactly why the guest's platform should
be chosen on its own merits -- minimal attack surface and fast boot for
short, disposable sessions (`docs/plan.md` Section 2.1) -- rather than
picked for consistency with whatever the host happens to run. A minimal,
security-focused guest distro is a stronger fit for "little for an
attacker to work with even if something went wrong inside it" than a
general-purpose server distro's full userland would be, regardless of
which host family `habitat` itself is validated against at a given
roadmap stage.

## Decision

The guest image is Alpine Linux, fixed for the guest's entire lifetime --
it does not have a roadmap of its own, and it does not track the host
roadmap (`0001-host-os-layer.md`: AlmaLinux for v1, Fedora for v1.1,
Ubuntu for v2). "AlmaLinux" / "Fedora" / "Ubuntu" describe the sequence
of platforms `habitat` itself is validated to run *on* (the host); the
guest is a separate, independently-chosen axis that stays Alpine
throughout that entire sequence.

Guest-side tooling (package management via `apk`, the default shell
being a POSIX/BusyBox `ash`, musl libc rather than glibc) is Alpine's own
and is not expected to shift as the host roadmap advances -- there is no
guest-side distro-conditional branching to add at any future host
roadmap stage, because the guest never changes with it.

## Consequences

- The disk-build pipeline (Phase 2), VM launch (Phase 3), and any
  guest-side assumptions baked into sync or egress tooling target
  Alpine's tooling and shell (`apk`, BusyBox `ash`, musl) from the start,
  and keep doing so at every future host roadmap stage -- there is no
  "guest tooling changes when the host stage changes" event to design
  for later.
- Any script or piece of guest-facing tooling that assumes a `bash`-only
  construct, or a `dnf`/`apt`-family package manager inside the guest,
  is a bug against this decision, not a reasonable default -- the guest
  is never dnf/rpm or apt/dpkg family, even while the *host* is.
- Guest image builds are versioned and validated on their own cadence
  (a pinned Alpine release line), independent of -- and not gated behind
  -- host roadmap-stage transitions.

## Correction (2026-09-15)

This ADR originally read "guest image mirrors the current host roadmap
stage, no separate guest-distro axis," reasoning that Podman + `krun`
removed any reason to pick the guest independently of the host. That
inverted the intended design: the actual, original intent was always a
fixed, minimal guest (Alpine) chosen independently of whatever the host
roadmap stage is -- the point above about Podman + `krun` removing a
*constraint* was correct, but it was misapplied as a reason to *couple*
guest and host rather than as the reason coupling was never necessary in
the first place. The Decision and Consequences sections above are the
corrected text, in place, per this repository's "one ADR per layer, no
supersession chain to walk" convention (`docs/decisions/README.md`,
following `0001-host-os-layer.md`'s own precedent of an inline,
dated amendment rather than a new numbered file). The original text is
not reproduced verbatim here since it named no bindings, code, or
executed decision that depended on its specific wording being
preserved -- only Phase 3's `guest_image` field and its accompanying
comment, both updated in the same change that added this correction.
