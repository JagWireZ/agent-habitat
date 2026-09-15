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

- `content_scan_ruleset_tamper.rs` (content-based secrets scanning):
  confirms a project's own `betterleaks.toml` can't be used to weaken or
  fully disable detection -- a catch-all `[allowlist]` regex hard-fails
  the build before anything is staged, and an empty project ruleset can't
  be read as "skip the baseline too" (the baseline is always present in
  the effective ruleset regardless of what the project supplies).

- `containment_escape.rs` (Phase 3): the mocked-launch-seam half of the
  containment story -- confirms the `podman run` argv this crate builds
  never includes a bind mount (`-v`, `--mount type=bind`), never widens
  host privilege (`--privileged`, `--cap-add`, `--pid=host`,
  `--network=host`, and similar), and defaults the guest's network to
  explicitly `none` rather than an unset default. This is *not* the exit
  gate's real escape-attempt test -- reaching host files/processes/network
  from inside an actually-booted guest needs real KVM, which neither this
  dev container nor this project's CI has, so that attempt is
  `tests/manual/validate-vm-launch.sh`'s job instead.

Phase 5 (egress-bypass) still needs real KVM and is not yet populated;
see `tests/manual/` for why it lands there instead once built.
