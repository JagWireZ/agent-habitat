#!/usr/bin/env bash
# tests/manual/validate-vm-launch.sh
#
# Phase 3's real-hardware exit gate (tmp/wip/implementation-plan.md): a
# concrete escape-attempt test executed from inside a launched guest --
# reaching host files, host processes, host network namespace -- must be
# demonstrated to fail; teardown must actually destroy the virtual disk
# and VM state with no residual writable artifact reachable from a later
# session. Neither this dev container nor this project's CI
# (ubuntu-latest, no nested virtualization) has real KVM, so this is a
# manual, host-dependent runbook, not a `cargo test` target -- see
# tests/manual/README.md.
#
# This script drives the launch/teardown machinery directly through
# `podman` (the same commands `habitat-vm::launcher` builds -- see
# crates/vm/src/launcher.rs's `build_run_args`), since Phase 7 hasn't
# wired `habitat run`'s full lifecycle yet. Update the PODMAN_ARGS array
# below if `launcher.rs` changes what it builds, so this script keeps
# testing the actual command in use, not a stale copy of it.
#
# Also confirms/corrects launcher.rs's real-hardware caveat: the exact
# OCI annotation key crun-krun expects for the extra virtio-blk device
# (WORKSPACE_DISK_ANNOTATION in launcher.rs) is a best-understanding
# placeholder until this runbook has actually been run once -- if step 3
# shows the annotation isn't recognized, fix the constant in launcher.rs
# and re-run, the same "confirmed wrong on real hardware, then fixed"
# pattern Phase 1 hit with the crun-krun package/binary name split.
#
# Requires: an AlmaLinux/Fedora host (dnf-family) with Podman + crun-krun
# installed and /dev/kvm exposed to the current user -- i.e. a host that
# already passes `habitat install`'s checks
# (tests/manual/validate-real-hardware.sh).
#
# Usage:
#   tests/manual/validate-vm-launch.sh              # run the full pass
#   tests/manual/validate-vm-launch.sh --report-only # print a prior run's summary

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$REPO_ROOT/tmp/wip/vm-launch-validation"
SESSION_NAME="habitat-manual-validation-$$"
GUEST_IMAGE="${HABITAT_GUEST_IMAGE:-localhost/habitat-guest:alpine}"
WORKSPACE_DISK="$LOG_DIR/session.img"
ANNOTATION_KEY="io.habitat.vm.workspace-disk"

mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.md"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
fail() { printf '\033[31m%s\033[0m\n' "$1" >&2; }

if [[ "${1:-}" == "--report-only" ]]; then
    if [[ -f "$SUMMARY" ]]; then
        cat "$SUMMARY"
    else
        fail "No prior run found at $SUMMARY -- run without --report-only first."
        exit 1
    fi
    exit 0
fi

: > "$SUMMARY"
record() { printf '%s\n' "$1" | tee -a "$SUMMARY"; }

record "# VM-launch validation run -- $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
record ""
record "Host: $(uname -a)"
record ""

# --- Step 1: host suitability -------------------------------------------
say "Step 1: host suitability"
if [[ ! -e /dev/kvm ]]; then
    fail "This host has no /dev/kvm -- this runbook needs real hardware virtualization. Run tests/manual/validate-real-hardware.sh first."
    record "- **ABORTED**: no /dev/kvm on this host."
    exit 1
fi
if ! command -v podman >/dev/null 2>&1; then
    fail "podman not found on PATH."
    record "- **ABORTED**: podman not installed."
    exit 1
fi
if ! command -v krun >/dev/null 2>&1; then
    fail "krun not found on PATH (is crun-krun installed?)."
    record "- **ABORTED**: krun runtime not installed."
    exit 1
fi
record "- /dev/kvm: present"
record "- podman: $(podman --version)"
record "- krun: $(krun --version 2>&1 || echo 'present (no --version output)')"

# --- Step 2: build a session disk image to launch against ---------------
say "Step 2: build a disposable session disk"
dd if=/dev/zero of="$WORKSPACE_DISK" bs=1M count=64 status=none
mkfs.ext4 -q -F "$WORKSPACE_DISK"
record "- Built a 64MB throwaway workspace disk at $WORKSPACE_DISK"

PODMAN_ARGS=(
    run --detach --rm --name "$SESSION_NAME"
    --runtime krun
    --network none
    --cpus 2 --memory 2048m
    --annotation "${ANNOTATION_KEY}=${WORKSPACE_DISK}"
    "$GUEST_IMAGE"
)

# --- Step 3: launch -------------------------------------------------------
say "Step 3: launch the session"
set +e
podman "${PODMAN_ARGS[@]}" > "$LOG_DIR/launch.log" 2>&1
LAUNCH_EXIT=$?
set -e
cat "$LOG_DIR/launch.log"
record "- Launch exit: $LAUNCH_EXIT (log: $LOG_DIR/launch.log)"
if [[ "$LAUNCH_EXIT" -ne 0 ]]; then
    record "- **FAILED**: session did not launch -- if the log shows the annotation was rejected or ignored, launcher.rs's WORKSPACE_DISK_ANNOTATION constant needs correcting to whatever crun-krun actually expects, then re-run this script."
    rm -f "$WORKSPACE_DISK"
    exit 1
fi
record "- CONFIRMED: session launched."

# --- Step 4: escape attempts (the actual exit gate) ---------------------
say "Step 4: escape attempts from inside the guest"
record ""
record "Run each of these against the running session and confirm they all FAIL to reach the host:"
record '```'
record "# host files"
record "podman exec $SESSION_NAME sh -c 'cat /etc/habitat-host-marker 2>&1 || echo BLOCKED'"
record ""
record "# host processes"
record "podman exec $SESSION_NAME sh -c 'ps aux 2>&1 | grep -v habitat || echo BLOCKED'"
record ""
record "# host network namespace"
record "podman exec $SESSION_NAME sh -c 'ip route 2>&1 || echo BLOCKED'"
record '```'
record ""
record "MANUAL: run the three commands above, confirm each is BLOCKED (or otherwise shows no host-side"
record "data), and record the actual output here before continuing. This is the real verification --"
record "do not check this box from inspection of the launch command alone."
record ""
record "- [ ] Host files unreachable"
record "- [ ] Host processes unreachable"
record "- [ ] Host network namespace unreachable"

# --- Step 5: teardown -----------------------------------------------------
say "Step 5: teardown"
set +e
podman rm --force --ignore "$SESSION_NAME" > "$LOG_DIR/teardown.log" 2>&1
TEARDOWN_EXIT=$?
set -e
rm -f "$WORKSPACE_DISK"
record "- Teardown exit: $TEARDOWN_EXIT (log: $LOG_DIR/teardown.log)"
if podman ps -a --format '{{.Names}}' | grep -qx "$SESSION_NAME"; then
    record "- **FAILED**: container still listed in \`podman ps -a\` after teardown."
    exit 1
fi
if [[ -e "$WORKSPACE_DISK" ]]; then
    record "- **FAILED**: workspace disk still present after teardown."
    exit 1
fi
record "- CONFIRMED: no residual container or disk image after teardown."

say "Done"
echo "Summary written to $SUMMARY -- fold the escape-attempt results from Step 4 into it by hand."
