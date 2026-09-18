# Architecture decisions, by layer

This directory holds one ADR per system layer (see `template.md` for the
format). There is no supersession chain to walk -- each file is the
current, standalone decision for its layer.

- [`0001-host-os-layer.md`](0001-host-os-layer.md) -- Linux-only host with
  hardware virtualization required; sequential distro roadmap (AlmaLinux
  -> Fedora -> Ubuntu); `habitat install`'s auto-install step detects the
  dnf/apt package-manager family as a narrow, amended exception.
- [`0002-guest-os-layer.md`](0002-guest-os-layer.md) -- guest image is
  fixed to Alpine, independent of whichever platform the host roadmap
  currently targets (corrected 2026-09-15; originally recorded the
  opposite -- see that file's "Correction" section).
- [`0003-container-engine-runtime-layer.md`](0003-container-engine-runtime-layer.md)
  -- rootless Podman launching each session through the `krun` OCI runtime
  (libkrun), not containerd/nerdctl + Kata Containers + Firecracker.
- [`0004-networking-layer.md`](0004-networking-layer.md) -- `passt` gives
  the guest a real virtual network interface; default-deny egress,
  filtered by destination at the local proxy.
- [`0005-storage-layer.md`](0005-storage-layer.md) -- disposable
  per-session staging directory, bind-mounted into the guest at
  `/workspace` (corrected 2026-09-18; originally a raw disk image attached
  as a `virtio-blk` block device -- see that file's "Correction" section).
- [`0006-distribution-packaging-layer.md`](0006-distribution-packaging-layer.md)
  -- `habitat` ships as prebuilt binaries/native packages, not built from
  source by operators.
- [`0007-content-secrets-scan-snapshot.md`](0007-content-secrets-scan-snapshot.md)
  -- content-based secrets scanning's effective ruleset is snapshotted
  once per session/build, never re-read on sync; records what Phase 4's
  sync/patch validation must do with a mid-session `betterleaks.toml`
  edit once that phase is built.
- [`0008-guest-exec-channel.md`](0008-guest-exec-channel.md) -- `podman
  exec` does not work against the `krun` runtime at all (confirmed on
  real hardware, and by upstream); the guest exec channel is per-session
  SSH over the same `passt` network Phase 5 already requires, not a
  custom protocol and not a revisit of `0003`'s runtime choice.
