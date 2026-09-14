# 0005. Storage layer: disposable per-session raw disk image attached as a virtio-blk block device

Status: accepted
Date: 2026-09-14

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

Each session gets its own disposable raw disk image, attached to the
guest as a `virtio-blk` block device -- never a live share or direct link
to the real project folder. The guest's own kernel mounts it; there is no
host-side loop-device step and no root-owned mountpoint, keeping storage
setup consistent with the rootless launch model. The agent works against
that disk, and only that disk. Host and sandbox are kept in sync
separately, at two well-defined moments (host to sandbox before each
prompt, sandbox to host after each tool call), via the same trusted patch
mechanism used for final promotion -- not through the block device itself.

## Consequences

- No live, always-on file-sharing process between host and sandbox is
  built (AGENTS.md Section 2, invariant 1) -- the block device is
  disposable, per-session storage, not a channel for the sync mechanism.
- Storage setup needs no privileged host-side mount step, matching
  `0003-container-engine-runtime-layer.md`'s rootless launch model.
- No simultaneous live access between host and guest is possible by
  construction; this trade-off is handled by the two-point sync mechanism
  instead, not by this layer.
- Sync performance at scale (large monorepos, large binary files) against
  this storage model is not yet validated -- called out in `docs/plan.md`
  Known limitations and AGENTS.md Section 3 as needing measurement before
  v1 ships.
