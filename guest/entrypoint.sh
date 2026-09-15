#!/bin/sh
# guest/entrypoint.sh -- this image's startup job: bring up the guest's
# network interface, install this session's authorized SSH key (passed
# in as the HABITAT_AUTHORIZED_KEY environment variable -- a public key,
# not a secret, see docs/decisions/0008-guest-exec-channel.md), and start
# sshd in the foreground, since podman exec does not work against the
# krun runtime at all and SSH is this project's real guest exec channel.
set -eu

HOME_DIR="/home/habitat"
SSH_DIR="$HOME_DIR/.ssh"
WORKSPACE_DIR="/workspace"

# Bring up the guest's network interface via DHCP
# (docs/decisions/0004-networking-layer.md). Alpine does not configure
# any interface on its own at boot -- normally that's OpenRC's
# networking service running `ifup`, which reads `/etc/network/interfaces`
# and invokes `udhcpc`; this entrypoint skips OpenRC entirely (same
# "skip the usual boot sequence" trade-off as the sshd privsep directory
# below), so nothing else ever asks for an address.
#
# Three real-hardware findings are baked into the four lines below, each
# confirmed via `tests/manual/validate-vm-launch.sh`:
#
# 1. `podman run --network pasta` alone is not sufficient for
#    `crun-krun` -- it also needs the `krun.use_passt=1` OCI annotation
#    (`habitat_vm::launcher::build_run_args`), and that annotation only
#    exists from `crun` 1.27.1 onward. Without both, the guest silently
#    boots under libkrun's default TSI networking instead (`tsi_hijack`
#    on the kernel command line, no virtio-net device at all) --
#    everything below assumes a real interface exists, which isn't a
#    given.
#
# 2. Interface name is discovered via `ip link show`, not
#    `/sys/class/net` -- this microVM boots via `/init.krun` as PID 1,
#    not a normal distro init, and `/sys` is not guaranteed to be
#    mounted (only `/proc` is, confirmed via `ps aux` elsewhere in this
#    project's manual runbooks). `dummy0` is excluded alongside `lo`: this
#    guest kernel auto-creates a `dummy0` placeholder (unrelated to real
#    networking, likely a built-in `dummy` driver default from
#    libkrunfw's kernel config) that sorts before the real virtio-net
#    device (`eth0`) in `ip link show`'s output -- excluding only `lo`
#    silently ran `udhcpc` against `dummy0` instead, which can never get
#    a lease while the real interface sat unconfigured.
#
# 3. The interface needs an explicit `ip link set ... up` before
#    `udhcpc` -- without it, `udhcpc` fails immediately on every attempt
#    with `sendto: Network is down`. virtio-net devices come up
#    administratively down by default here, unlike a typical distro boot
#    where udev/networkd/ifup already brought every interface up before
#    DHCP ever runs.
#
# Not fatal if any of this fails, same posture as the workspace-disk
# mount below: DHCP not completing shouldn't take down the SSH exec
# channel. `timeout 10` is a deliberate second layer of defense on top
# of `udhcpc -n`'s own give-up behavior, since an earlier, less-defended
# version of this step hung the whole boot silently on a bad assumption.
GUEST_IFACE="$(ip -o link show 2>/dev/null | cut -d: -f2 | tr -d ' ' | grep -Ev '^(lo|dummy[0-9]*)$' | head -n1)"
if [ -z "$GUEST_IFACE" ]; then
    echo "habitat-entrypoint: WARNING: no non-loopback network interface found via 'ip link show' -- network will NOT be configured; run 'ip link show' from inside this guest to find the real interface name" >&2
elif ! ip link set "$GUEST_IFACE" up; then
    echo "habitat-entrypoint: WARNING: 'ip link set $GUEST_IFACE up' failed -- network will NOT be configured" >&2
elif ! timeout 10 udhcpc -i "$GUEST_IFACE" -n -q -t 5 >/dev/null 2>&1; then
    echo "habitat-entrypoint: WARNING: udhcpc on $GUEST_IFACE did not obtain a DHCP lease within 10s -- network will NOT be configured" >&2
fi
# `-q` exits udhcpc once the interface is configured rather than staying
# resident to renew the lease later -- a deliberate simplification for
# this project's short-lived, disposable sessions (`docs/plan.md`), not
# an oversight. A session that outlives its lease is a real scenario to
# revisit if/when sessions stop being short-lived.

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
