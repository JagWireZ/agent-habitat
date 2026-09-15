#!/bin/sh
# guest/entrypoint.sh -- this image's only startup job: install this
# session's authorized SSH key (passed in as the HABITAT_AUTHORIZED_KEY
# environment variable -- a public key, not a secret, see
# docs/decisions/0008-guest-exec-channel.md) and start sshd in the
# foreground, since podman exec does not work against the krun runtime
# at all and SSH is this project's real guest exec channel.
set -eu

HOME_DIR="/home/habitat"
SSH_DIR="$HOME_DIR/.ssh"
WORKSPACE_DIR="/workspace"

# Mount the session's workspace disk (docs/decisions/0005-storage-layer.md:
# "the guest's own kernel mounts it" -- no host-side loop device, no
# root-owned host mountpoint). The container's own rootfs comes in via
# virtiofs, not a block device, so the launcher's virtio-blk workspace
# disk is the only /dev/vd* device present; it's a raw ext4 filesystem
# with no partition table (crate::workspace::diskimage builds it via
# `mke2fs -d <staging-dir>` directly), so it shows up as a whole disk, not
# a partition -- pick the first /dev/vd* found rather than hardcoding a
# name, since which one crun-krun assigns is exactly the kind of thing
# this project's `tests/manual/` runbooks exist to confirm on real
# hardware.
WORKSPACE_DEV=""
for dev in /dev/vd*; do
    [ -b "$dev" ] || continue
    WORKSPACE_DEV="$dev"
    break
done
mkdir -p "$WORKSPACE_DIR"
# Not fatal (yet): this device-detection guess is unconfirmed on real
# crun-krun hardware (same "best current understanding" caveat as
# launcher.rs's WORKSPACE_DISK_ANNOTATION). Warn loudly and keep booting
# -- an unmounted /workspace breaks sync, but killing sshd here would
# also break the SSH exec channel itself, which is a much worse failure
# mode to debug from the outside. `ls /dev` from inside a reachable guest
# is exactly what should fix this detection logic once run for real.
if [ -z "$WORKSPACE_DEV" ]; then
    echo "habitat-entrypoint: WARNING: no virtio-blk workspace device found under /dev/vd* -- /workspace will NOT be mounted; run 'ls -la /dev' from inside this guest to find the real device name" >&2
elif ! mount -t ext4 "$WORKSPACE_DEV" "$WORKSPACE_DIR"; then
    echo "habitat-entrypoint: WARNING: mount -t ext4 $WORKSPACE_DEV $WORKSPACE_DIR failed -- /workspace will NOT be mounted" >&2
fi
chown habitat:habitat "$WORKSPACE_DIR"

mkdir -p "$SSH_DIR"
if [ -n "${HABITAT_AUTHORIZED_KEY:-}" ]; then
    printf '%s\n' "$HABITAT_AUTHORIZED_KEY" > "$SSH_DIR/authorized_keys"
else
    # Fail closed, not open: no key means no way in, never "accept
    # anything" -- an empty authorized_keys file, not a missing check.
    : > "$SSH_DIR/authorized_keys"
fi
chmod 700 "$SSH_DIR"
chmod 600 "$SSH_DIR/authorized_keys"
chown -R habitat:habitat "$SSH_DIR"

# sshd's privilege-separation directory: normally created by Alpine's
# sshd OpenRC init script before sshd starts. This entrypoint execs sshd
# directly instead of going through OpenRC, and /run is a fresh tmpfs
# every boot, so nothing else creates this -- without it sshd refuses to
# start at all ("Missing privilege separation directory").
mkdir -p /run/sshd

exec /usr/sbin/sshd -D -e
