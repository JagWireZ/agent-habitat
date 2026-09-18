# 0010. Workspace disk attachment (0005) does not work on real crun-krun -- storage mechanism must change

Status: proposed
Date: 2026-09-18

## Context

`0005-storage-layer.md` decided that each session's workspace would be a
disposable raw disk image, attached to the guest as a `virtio-blk` block
device via the OCI annotation `io.habitat.vm.workspace-disk`
(`habitat_vm::launcher::WORKSPACE_DISK_ANNOTATION`,
`crates/vm/src/launcher.rs:34`). That module's own doc comment already
flagged the annotation as "this launcher's current best understanding,
not yet confirmed against real crun-krun." It has now been confirmed --
and it is wrong.

Real-hardware findings (this host: Fedora 44, crun 1.29.1, libkrun
1.19.0 -- the newest builds available, matching what `habitat install`
pins):

- `man krun` and `strings` on the installed `crun` binary confirm the
  **complete** list of OCI annotations (and `.krun_vm.json` fields) this
  runtime supports: `krun.cpus`, `krun.ram_mib`, `krun.gpu_flags`,
  `krun.use_passt`, `krun.nested_virt`, `krun.variant`, plus
  `virtiofs_tag`/`virtiofs_shm_size` for the *root* filesystem share.
  There is no mechanism, under any name, for attaching a second
  virtio-blk disk.
- Launching a guest by hand with `WORKSPACE_DISK_ANNOTATION` set (the
  exact flag `build_run_args` emits) confirms this directly: no
  `/dev/vd*` device ever appears inside the guest. `guest/entrypoint.sh`'s
  mount step is coded as non-fatal (deliberately, so a failure here
  doesn't also take down the SSH exec channel), so the session boots
  successfully and looks healthy right up until the first sync round,
  which fails every time with "not a git repository" -- `/workspace` is
  just the empty directory `entrypoint.sh` created, never the git-seeded
  staging content the build pipeline produced.
- This is not project-size-dependent or intermittent: it fails on every
  session, for every project, because the attachment mechanism 0005
  specified does not exist in this runtime.
- Separately, and independently discovered while investigating: `-v
  hostdir:/workspace` (a real bind mount) *does* work on this same
  runtime -- confirmed by hand, mounted via virtiofs, content visible
  and readable/writable inside the guest.

**What 0005 was actually trying to buy:** no live, always-on channel
between host and guest (AGENTS.md Section 2 invariant 1 -- the two-point
sync mechanism is the only sanctioned bridge), and no privileged
host-side mount step (consistent with `0003`'s rootless launch model).
The virtio-blk mechanism was one way to get both properties; it happens
not to be available here. `0004`/`0008` already have precedent for this
project correcting a real-hardware-invalidated assumption after the fact
(TSI vs. `pasta` networking; `podman exec` vs. SSH) rather than treating
the original ADR as untouchable.

A second effect of this same broken mechanism: `DEFAULT_IMAGE_SIZE_MB`
(`crates/cli/src/run.rs:49`) fixes every session's disk image at 4096 MB
regardless of project size (16 MB for this repo), which is wasted disk
regardless of which fix below is chosen -- if the disk image goes away
entirely (Option A), this problem disappears with it; if it stays
(Option B), it still needs its own fix, sized to the actual project.

## Options

### Option A -- bind-mount the disposable staging copy instead of a disk image

Drop the disk-image build step (`diskimage.rs`'s `mke2fs -d` /
`assemble_disk_image`) entirely. `pipeline::build` still produces the
git-seeded staging directory it does today; `launcher::build_run_args`
mounts *that staging directory* into the guest at `/workspace` via `-v`,
the same mechanism confirmed working above.

**Pros**
- Confirmed to work on real hardware today, no dependency on a runtime
  feature that doesn't exist.
- Deletes code rather than adding it: no disk-image assembly, no
  guest-side device-detection/mount-retry logic in `entrypoint.sh`.
- Solves the 4096 MB problem as a side effect -- there is no fixed-size
  image to sanely size in the first place.
- Still a disposable *copy*, not the operator's real project directory --
  `project_root` itself is never the bind-mount source, matching the
  original "never touches the real project" property.

**Cons**
- Weakens the containment property `0005` bought via the block device:
  a bind mount is a *live* channel for as long as the container runs,
  not a one-shot, disposable copy sealed at boot. `tests/adversarial/
  containment_escape.rs:29` currently asserts, as a hard invariant, that
  `build_run_args` never emits a `-v`/`--mount type=bind` flag at all --
  this option requires deliberately relaxing that specific test, not
  just updating it to match new argv.
- Blast radius on any host-side path-handling bug (a symlink inside the
  staged copy, a `..` escape) is now "whatever the staging directory's
  parent allows," not "nothing, because no host path is ever passed to
  `podman run`." Low probability given `staging::build_staging_dir`
  already skips symlinks outright, but not zero.
- `tests/manual/validate-vm-launch.sh`'s escape-attempt suite (host
  files/processes/network unreachable from the guest) has never been run
  against a bind-mounted workspace -- it should be re-run and its results
  recorded before trusting this mechanism the way `0005`'s virtio-blk
  design was trusted after that same suite passed.

### Option B -- keep virtio-blk, get libkrun to actually support it

Investigate whether a newer/differently-built libkrun exposes real
extra-disk attachment (`strings` on `crun` shows it already expects a
`krun_add_virtiofs2` symbol this host's libkrun 1.19.0 doesn't provide,
suggesting the *intended* multi-mount mechanism going forward is another
virtiofs tag, not a virtio-blk disk at all) and pin to that build,
following the same "pinned Koji build" pattern `0001`'s install checks
already use for `crun-krun`/`libkrunfw`.

**Pros**
- Preserves `0005`'s original design and its stronger isolation property
  (disposable image, no live channel) without compromise.
- Consistent with this project's existing precedent of pinning exact
  known-good builds (`checks::MIN_CRUN_VERSION_FOR_PASST`,
  `LIBKRUNFW_FALLBACK_URL`) rather than accepting whatever a distro
  repo ships.

**Cons**
- 1.19.0 is already the newest libkrun available via Fedora's `updates`
  repo -- there is no newer packaged build to fall back to the way
  `0001`'s crun-krun fallback uses a specific Koji build. Getting real
  disk-attachment support means either building libkrun from source
  against a version that has it (unconfirmed one exists) or waiting on
  upstream, neither of which is a short-term fix.
- Blocks `habitat run` from working at all in the meantime -- every
  session fails the same way it does today, for an unknown duration.
- Adds a second pinned-build dependency (`0001`'s pattern was already
  needed once for crun/crun-krun and once for libkrunfw; this would be a
  third), each one more thing `habitat install` has to detect, fetch, and
  keep current.

### Option C -- fix only the disk-size waste, leave sync broken

Make `DEFAULT_IMAGE_SIZE_MB` scale to the actual staging directory size
instead of a flat 4096, but leave the virtio-blk attachment (and
therefore every `habitat run` session) broken.

**Pros**
- Small, low-risk, no security-invariant discussion needed.

**Cons**
- Does not make `habitat run` usable -- the tool's core function stays
  broken for every project, every session. Not a real option on its own,
  only useful as a stopgap alongside deciding between A and B.

## Consequences (of not deciding yet)

`habitat run` cannot complete a session today regardless of project
size or config -- this is not a corner case to route around, it is the
main path. Whichever of A/B is chosen, `0005-storage-layer.md` will need
a correction section (matching the precedent already set in
`0002-guest-os-layer.md` and `0004-networking-layer.md`'s own
real-hardware corrections), and `tests/manual/validate-vm-launch.sh`
should gain an explicit "is `/workspace` actually populated inside the
guest" check -- its current pass record only confirmed the container
booted and SSH worked, never that the workspace mechanism itself
functioned, which is how this shipped unnoticed.
