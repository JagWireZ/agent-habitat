# guest/ -- the guest image

Builds and locally tags Agent Habitat's guest image,
`localhost/habitat-guest:alpine` -- the exact image reference
`habitat_vm::launcher` boots via crun-krun (`crates/vm/src/launcher.rs`)
and every `tests/manual/` runbook expects to find already present.

- `Containerfile` -- fixed to Alpine, independent of the host roadmap
  (`docs/decisions/0002-guest-os-layer.md`, corrected 2026-09-15).
  Deliberately minimal: only `git` is installed beyond the base image,
  since that's the only guest-side binary the two-point sync mechanism
  actually invokes via `podman exec`
  (`crates/workspace/src/{sync,guest_exec}.rs`).
- `build.sh` -- builds and tags the image. Run this once (and again
  after any `Containerfile` change) before attempting a launch, real or
  via a `tests/manual/` runbook:

  ```
  guest/build.sh
  ```

Nothing in `habitat run`'s own path builds this automatically yet --
that's Phase 7 territory (`tmp/wip/implementation-plan.md`), not this
directory's job. Until then, a `podman run` against
`localhost/habitat-guest:alpine` before this script has ever been run
will fail trying to pull a nonexistent image from a registry named
`localhost` -- that failure means "build the guest image first," not a
launch-flag or annotation problem.
