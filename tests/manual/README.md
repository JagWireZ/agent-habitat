# tests/manual/

Host-dependent runbooks that a human runs deliberately against real
hardware -- not `cargo test` targets, and not something CI can run, since
they need a specific class of real machine (e.g. dnf-family with hardware
virtualization exposed) plus `sudo` and, for their negative cases,
someone's explicit decision to temporarily break something on that
machine.

This sits alongside `tests/unit/<domain>/`, `tests/integration/`, and
`tests/adversarial/` (see `file-structure.md`) rather than inside any of
them: those three are all automated, in-process test suites that mirror
or cut across the crate tree; what lives here is scripted-but-manual
validation that exists specifically because some part of the system can't
be verified any other way (e.g. `/dev/kvm` behavior, a real package
manager, a real `sudo` prompt).

- `validate-real-hardware.sh` -- Phase 1's remaining real-hardware exit
  gate (`tmp/wip/phase-1-tasks.md` §10): confirms `habitat install`/
  `habitat run` behave correctly on a real dnf-family host (AlmaLinux/
  Fedora) with virtualization enabled. Reused, not duplicated, at Phase
  8's validation run-book.
