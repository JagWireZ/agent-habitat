# tests/adversarial/

Containment-escape attempts (Phase 3) and egress-bypass attempts
(Phase 5) live together here, per `file-structure.md` and AGENTS.md
Section 6 ("test locations should mirror source locations... adversarial
tests cover egress bypass attempts and containment-escape attempts
together").

These are "verify before trusting" tests (AGENTS.md Section 3): required,
recorded, re-run after any relevant ruleset change -- not optional
hardening nice-to-haves.

**Populated so far:**

- `blocklist_disk_image.rs` (Phase 2): seeds a project with a variant of
  every default blocklist pattern (`policy/blocklist.txt`), each carrying
  a unique secret value, runs the real disk-build pipeline, then confirms
  none of those files or secret values appear anywhere in the
  intermediate staging directory *or* on the actual built disk image
  (extracted back out via `debugfs`, no mount, no root). Unlike Phase
  3/5's KVM-dependent adversarial tests, this one needs no real
  hardware -- `git`/e2fsprogs are ordinary tooling present in this dev
  container and in CI, so it runs for real here rather than deferring to
  `tests/manual/`.

Phase 3 (containment-escape) and Phase 5 (egress-bypass) still need
real KVM and are not yet populated; see `tests/manual/` for why those
two land there instead once built.
