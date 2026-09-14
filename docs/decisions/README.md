# Architecture decisions, by layer

This directory holds one ADR per system layer (see `template.md` for the
format). There is no supersession chain to walk -- each file is the
current, standalone decision for its layer.

- [`0001-host-os-layer.md`](0001-host-os-layer.md) -- Linux-only host with
  hardware virtualization required; sequential distro roadmap (AlmaLinux
  -> Fedora -> Ubuntu).
- [`0002-guest-os-layer.md`](0002-guest-os-layer.md) -- guest image mirrors
  whichever platform the host roadmap currently targets; no separate
  guest-distro axis.
- [`0003-container-engine-runtime-layer.md`](0003-container-engine-runtime-layer.md)
  -- rootless Podman launching each session through the `krun` OCI runtime
  (libkrun), not containerd/nerdctl + Kata Containers + Firecracker.
- [`0004-networking-layer.md`](0004-networking-layer.md) -- `passt` gives
  the guest a real virtual network interface; default-deny egress,
  filtered by destination at the local proxy.
- [`0005-storage-layer.md`](0005-storage-layer.md) -- disposable
  per-session raw disk image attached as a `virtio-blk` block device; no
  live share.
- [`0006-distribution-packaging-layer.md`](0006-distribution-packaging-layer.md)
  -- `habitat` ships as prebuilt binaries/native packages, not built from
  source by operators.
