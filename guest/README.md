# guest/ -- the guest image

Builds and locally tags Agent Habitat's guest image,
`localhost/habitat-guest:alpine` -- the exact image reference
`habitat_vm::launcher` boots via crun-krun (`crates/vm/src/launcher.rs`)
and every `tests/manual/` runbook expects to find already present.

- `Containerfile` -- fixed to Alpine, independent of the host roadmap
  (`docs/decisions/0002-guest-os-layer.md`, corrected 2026-09-15).
  Deliberately minimal: `git` (the only guest-side binary the two-point
  sync mechanism actually invokes), `openssh-server` -- because `podman
  exec` does not work against the `krun` runtime at all (confirmed on
  real hardware and by upstream:
  [containers/crun#2090](https://github.com/containers/crun/issues/2090)),
  so SSH is the real guest exec channel
  (`docs/decisions/0008-guest-exec-channel.md`), not an optional extra --
  and `curl`, which `tests/manual/validate-egress.sh`'s connection-trace
  exit gate runs from inside the guest.
- `entrypoint.sh` -- installs this session's authorized SSH key (passed
  in via the `HABITAT_AUTHORIZED_KEY` environment variable -- a public
  key, never a secret) and starts `sshd` in the foreground.
- `build.sh` -- builds and tags the image. Run this once (and again
  after any `Containerfile`/`entrypoint.sh` change) before attempting a
  launch, real or via a `tests/manual/` runbook:

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
