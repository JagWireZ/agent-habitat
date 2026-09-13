# 0002. Guest distro is AlmaLinux-only in v1

Status: superseded by 0003
Date: 2026-09-13

> Superseded 2026-09-13: this decision conflated guest and host OS scope.
> The AlmaLinux/Fedora/Ubuntu roadmap described below was always meant to
> describe the **host** OS (the machine running `habitat`), not the guest
> -- the guest is fixed at a minimal Alpine Linux image throughout
> (`docs/plan.md` Section 2.1) and was never meant to have a distro
> roadmap of its own. See
> `0003-fedora-and-ubuntu-based-host-in-v1.md` for the corrected,
> host-scoped decision. Kept here, unmodified below, as the historical
> record of the decision it replaces.

## Context

The guest is the environment the agent actually works in inside the
microVM. Validating containment, secrets filtering, sync, and egress
control end-to-end requires picking one guest distro to prove the whole
stack against first, rather than spreading validation effort across
several distros before any of them is proven.

AlmaLinux, Fedora, and Ubuntu differ enough under the hood (package
tooling, init behavior, and -- in Ubuntu's case per `docs/plan.md`
Section 5 -- a different security model) that supporting more than one
from the start would multiply the validation surface before v1's core
claims (real VM isolation, fail-closed preflight, blocklist-before-copy,
two-point sync, default-deny egress) have been shown to hold for even one.

## Decision

v1 targets AlmaLinux as the only guest distro. Fedora (v1.1) is expected
to be a light lift given its similarity to AlmaLinux, but still requires
its own validation pass rather than being assumed free. Ubuntu (v2) is
deferred further because its different security model needs its own
review, not a port of AlmaLinux's. No Fedora- or Ubuntu-specific guest
code paths are to be built before their respective roadmap stage starts
(AGENTS.md Section 5).

## Consequences

- The disk-build pipeline (Phase 2), VM launch (Phase 3), and any
  guest-side assumptions baked into sync or egress tooling may assume
  AlmaLinux-specific package layout and tooling for v1 -- they are not
  required to be distro-agnostic from day one.
- Distro-conditional branches for Fedora or Ubuntu do not belong in the
  codebase until v1.1 / v2 actually start, per AGENTS.md Section 5's
  build-order rules.
- The roadmap sequence (AlmaLinux -> Fedora -> Ubuntu) is strict: work on
  a later guest does not begin until the earlier one has shipped and been
  validated end-to-end on real hardware (see the Phase 8 validation
  run-book in the implementation plan).
