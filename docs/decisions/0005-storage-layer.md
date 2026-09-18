# 0005. Storage layer: disposable per-session staging directory, bind-mounted into the guest

Status: accepted
Date: 2026-09-14
Corrected: 2026-09-18 (see "Correction" below -- the original attachment
mechanism does not exist on real hardware; the property it was chosen for
is preserved through a different mechanism)

## Context

The workspace the agent operates on needs to be fully isolated from the
host's real files (`docs/plan.md` Section 2.2), and setting it up should
not require host-side privilege that would sit at odds with the rootless
launch model (`0003-container-engine-runtime-layer.md`). A live, always-on
file share was already ruled out as a design matter (AGENTS.md Section 2,
invariant 1) because it would mean a background process constantly
bridging host and sandbox -- itself a security risk, and a route around
the two-point sync mechanism.

A host-side loop-device mount or a root-owned mountpoint would work, but
either reintroduces a privileged host-side step that the rootless launch
model (Podman with no daemon, no elevated launcher) otherwise avoids
entirely.

## Decision

Each session gets its own disposable, git-seeded staging directory, bind-
mounted into the guest at `/workspace` -- never a live share or direct
link to the real project folder. There is no host-side loop-device step
and no root-owned mountpoint, keeping storage setup consistent with the
rootless launch model. The agent works against that staging directory,
and only that staging directory. Host and sandbox are kept in sync
separately, at two well-defined moments (host to sandbox before each
prompt, sandbox to host after each tool call), via the same trusted patch
mechanism used for final promotion -- not through the bind mount itself,
which only ever carries the disposable staging copy, never `project_root`
or any other arbitrary host path.

## Consequences

- No live, always-on file-sharing process between host and sandbox is
  built (AGENTS.md Section 2, invariant 1) -- the bind-mounted directory
  is disposable, per-session storage, not a channel for the sync
  mechanism. Continuous write access to that disposable copy for the life
  of the session is an accepted, deliberate narrowing of the stronger
  "no live channel at all" property the original block-device design had
  (see Correction below), not an oversight.
- Storage setup needs no privileged host-side mount step, matching
  `0003-container-engine-runtime-layer.md`'s rootless launch model.
- No simultaneous live access between host and guest to the *real*
  project directory is possible by construction, regardless of the
  staging directory's own bind-mount lifetime; this trade-off is handled
  by the two-point sync mechanism, not by this layer.
- Sync performance at scale (large monorepos, large binary files) against
  this storage model is not yet validated -- called out in `docs/plan.md`
  Known limitations and AGENTS.md Section 3 as needing measurement before
  v1 ships.
- Workspace size is bounded only by host disk space -- there is no
  fixed-size image to cap it, and no separate size guard is added for
  v1.

## Correction (2026-09-18)

This ADR originally decided on a disposable raw disk image, attached to
the guest as a `virtio-blk` block device, with the guest's own kernel
mounting it. Real-hardware testing (Fedora 44, crun 1.29.1, libkrun
1.19.0 -- the newest available builds, matching what `habitat install`
pins) confirmed that mechanism does not exist in this runtime at all:
`man krun` and `strings` on the installed `crun` binary show the complete
list of supported OCI annotations and `.krun_vm.json` fields (`krun.cpus`,
`krun.ram_mib`, `krun.gpu_flags`, `krun.use_passt`, `krun.nested_virt`,
`krun.variant`, plus `virtiofs_tag`/`virtiofs_shm_size` for the *root*
filesystem share only) -- there is no mechanism, under any name, for
attaching a second virtio-blk disk. Launching a guest by hand with the
annotation `build_run_args` used to emit (`io.habitat.vm.workspace-disk`)
confirmed this directly: no `/dev/vd*` device ever appeared inside the
guest, so `/workspace` stayed the empty directory `entrypoint.sh` created,
and every session's first sync round failed with "not a git repository."
This was not project-size-dependent or intermittent -- it failed on every
session, for every project, because the attachment mechanism this ADR
specified does not exist in this runtime. (Full investigation record:
`0010-workspace-disk-attachment-broken.md`, folded into this correction
and slated for deletion once the migration below is verified complete.)

Separately confirmed working on the same hardware: `-v hostdir:/workspace`
(a real bind mount), mounted via virtiofs, content visible and
readable/writable inside the guest.

**What this ADR was actually trying to buy:** no live, always-on channel
between host and guest (AGENTS.md Section 2 invariant 1 -- the two-point
sync mechanism is the only sanctioned bridge), and no privileged host-side
mount step (consistent with `0003`'s rootless launch model). The
virtio-blk mechanism was one way to get both properties; it is not
available here. The corrected Decision above keeps both properties for
the *real* project directory -- it is never bind-mounted, never a live
share, and the two sync moments remain the only path for it to change --
by narrowing scope to the disposable staging copy instead: that copy is
now intentionally, continuously bind-mounted for the life of the session,
but it is only ever populated in the first place via the existing
blocklist-gated pipeline, and it is still a disposable *copy*, not the
operator's real project directory.

This trades away part of the original property (the disposable copy is
now a live channel for the container's lifetime, not a one-shot copy
sealed at boot) for a mechanism that actually works on real hardware, and
also resolves a second problem the block-device design had: a disk image
fixed at a flat size regardless of project size (4096 MB, wasteful for
small projects) no longer exists to size at all -- workspace size is
simply bounded by host disk space now. `tests/adversarial/
containment_escape.rs` needs updating accordingly, to assert the bind
mount present is *only* the expected staging directory (never
`project_root` or any other host path), rather than asserting no bind
mount ever appears.
`tests/manual/validate-vm-launch.sh`'s escape-attempt suite still needs to
be re-run against the bind-mounted workspace to confirm containment holds
under the new mechanism, per AGENTS.md Section 3's "verify before
trusting" discipline -- it has never been exercised against this
mechanism, and results should be recorded in
`tmp/wip/vm-launch-validation/summary.md` (or a fresh dated run) once that
happens.

This is the same "confirmed wrong on real hardware, then corrected in
place" pattern already used by `0002-guest-os-layer.md`'s and
`0008-guest-exec-channel.md`'s own corrections, per this repository's
"one ADR per layer, no supersession chain" convention
(`docs/decisions/README.md`).
