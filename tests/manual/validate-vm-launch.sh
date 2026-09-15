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
# Step 4's escape attempts run automatically, from this script, against
# the still-live session -- they are not printed as instructions for a
# human to copy into a second terminal. An earlier version did exactly
# that, and teardown ran before anyone had a window to act on them, so
# the checkboxes stayed unchecked with nothing actually verified. Only
# the network-route comparison still needs a human's eyes (there's no
# single substring that reliably proves "not the host's real routes").
#
# **Guest exec channel is SSH, not `podman exec`**
# (docs/decisions/0008-guest-exec-channel.md): a real run confirmed
# `podman exec` does not work against the `krun` runtime at all ("the
# handler does not support exec") -- an upstream limitation, not
# something specific to this script. This script generates its own
# throwaway session keypair and bakes the public half into the guest via
# `--env`, exactly as `habitat_vm::launcher::build_run_args` does.
#
# This script drives the launch/teardown machinery directly through
# `podman` (the same commands `habitat-vm::launcher` builds -- see
# crates/vm/src/launcher.rs's `build_run_args`), since Phase 7 hasn't
# wired `habitat run`'s full lifecycle yet. Update the PODMAN_ARGS array
# below if `launcher.rs` changes what it builds, so this script keeps
# testing the actual command in use, not a stale copy of it.
#
# Also confirms/corrects launcher.rs's real-hardware caveats: the exact
# OCI annotation key crun-krun expects for the extra virtio-blk device
# (WORKSPACE_DISK_ANNOTATION), and the `podman inspect` format string
# used to resolve the guest's address (GUEST_ADDRESS_INSPECT_FORMAT) --
# both are best-understanding placeholders until this runbook has
# actually been run once, the same "confirmed wrong on real hardware,
# then fixed" pattern Phase 1 hit with the crun-krun package/binary name
# split.
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
SSH_KEY_PATH="$LOG_DIR/session-key"
GUEST_ADDRESS_INSPECT_FORMAT='{{.NetworkSettings.IPAddress}}'

mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.md"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
fail() { printf '\033[31m%s\033[0m\n' "$1" >&2; }

# Every SSH/SCP call to the guest in this script uses these options --
# matches `habitat_workspace::guest_exec::ssh_option_args` exactly, so
# this script keeps exercising the real client-side flags in use.
SSH_OPTS=(-i "$SSH_KEY_PATH" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes)

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
for bin in podman krun ssh ssh-keygen; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        fail "$bin not found on PATH."
        record "- **ABORTED**: $bin not installed."
        exit 1
    fi
done
record "- /dev/kvm: present"
record "- podman: $(podman --version)"
record "- krun: $(krun --version 2>&1 || echo 'present (no --version output)')"
record "- ssh: $(ssh -V 2>&1)"

# --- Step 1b: ensure the guest image actually exists locally -----------
say "Step 1b: guest image"
if ! podman image exists "$GUEST_IMAGE"; then
    if [[ "$GUEST_IMAGE" == "localhost/habitat-guest:alpine" ]]; then
        record "- $GUEST_IMAGE not found locally -- building it via guest/build.sh"
        "$REPO_ROOT/guest/build.sh"
    else
        fail "$GUEST_IMAGE (from \$HABITAT_GUEST_IMAGE) not found locally, and it isn't the default this script knows how to build. Build or pull it yourself first."
        record "- **ABORTED**: $GUEST_IMAGE not present and not buildable by this script."
        exit 1
    fi
fi
record "- guest image present: $GUEST_IMAGE"

# --- Step 1c: generate this session's ephemeral SSH keypair -------------
say "Step 1c: session SSH keypair (guest exec channel)"
rm -f "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_PATH" -C habitat-session -q
AUTHORIZED_KEY="$(cat "$SSH_KEY_PATH.pub")"
record "- Generated a fresh ed25519 keypair at $SSH_KEY_PATH (never reused, deleted at teardown)."

# --- Step 2: build a session disk image to launch against ---------------
say "Step 2: build a disposable session disk"
dd if=/dev/zero of="$WORKSPACE_DISK" bs=1M count=64 status=none
mkfs.ext4 -q -F "$WORKSPACE_DISK"
record "- Built a 64MB throwaway workspace disk at $WORKSPACE_DISK"

PODMAN_ARGS=(
    run --detach --rm --name "$SESSION_NAME"
    --runtime krun
    # Matches habitat_vm::launcher's current build_run_args (Phase 5):
    # a pasta-backed network with DNS pinned to a proxy address, never
    # the Phase 3 `--network none` placeholder or libkrun's default TSI
    # mode. No real proxy is actually running for this script's own
    # purpose (a containment escape attempt, not an egress trace --
    # that's tests/manual/validate-egress.sh's job), so this address is
    # a placeholder the guest's DNS won't actually be able to reach; that
    # doesn't affect this script's own checks.
    --network pasta
    --dns 127.0.0.1
    --cpus 2 --memory 2048m
    --annotation "${ANNOTATION_KEY}=${WORKSPACE_DISK}"
    --env "HABITAT_AUTHORIZED_KEY=${AUTHORIZED_KEY}"
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
    rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
    exit 1
fi
record "- CONFIRMED: session launched."

# --- Step 3b: resolve the guest's address --------------------------------
say "Step 3b: resolve the guest's address"
# Always dump the full inspect JSON, before trying the format string --
# so a failure here leaves something to actually diagnose from, instead
# of just "it was empty, guess again." pasta is a fundamentally
# different networking mode from Podman's own bridge/CNI stack, so
# `.NetworkSettings.IPAddress` (which this constant currently guesses)
# may simply not apply to it -- see GUEST_ADDRESS_INSPECT_FORMAT's doc
# comment in launcher.rs for this real-hardware caveat.
podman inspect "$SESSION_NAME" > "$LOG_DIR/inspect.json" 2>&1 || true
GUEST_ADDR="$(podman inspect --format "$GUEST_ADDRESS_INSPECT_FORMAT" "$SESSION_NAME" 2>/dev/null | tr -d '[:space:]')"
record "- \`podman inspect --format '$GUEST_ADDRESS_INSPECT_FORMAT' $SESSION_NAME\` -> \`$GUEST_ADDR\`"
if [[ -z "$GUEST_ADDR" ]]; then
    record "- Full inspect output saved to $LOG_DIR/inspect.json. NetworkSettings block:"
    record '```'
    if command -v jq >/dev/null 2>&1; then
        jq '.[0].NetworkSettings' "$LOG_DIR/inspect.json" 2>&1 | tee -a "$SUMMARY"
    else
        NET_LINE="$(grep -n '"NetworkSettings"' "$LOG_DIR/inspect.json" || true)"
        record "jq not available -- NetworkSettings starts around: $NET_LINE (see $LOG_DIR/inspect.json directly)"
    fi
    record '```'
    record "- **FAILED**: empty guest address. Find the field/path pasta actually populates in the"
    record "  block above, then update GUEST_ADDRESS_INSPECT_FORMAT in this script and"
    record "  \`habitat_vm::launcher::GUEST_ADDRESS_INSPECT_FORMAT\` to match, then re-run."
    podman rm --force --ignore "$SESSION_NAME" >/dev/null 2>&1 || true
    rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
    exit 1
fi

say "Waiting for sshd to accept connections"
SSH_READY=0
for _ in $(seq 1 30); do
    if ssh "${SSH_OPTS[@]}" "habitat@$GUEST_ADDR" true 2>/dev/null; then
        SSH_READY=1
        break
    fi
    sleep 1
done
if [[ "$SSH_READY" -ne 1 ]]; then
    record "- **FAILED**: could not SSH into the guest at $GUEST_ADDR within 30s -- confirm guest/entrypoint.sh actually starts sshd, and that GUEST_ADDR is reachable from the host."
    podman rm --force --ignore "$SESSION_NAME" >/dev/null 2>&1 || true
    rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
    exit 1
fi
record "- CONFIRMED: SSH exec channel reachable at habitat@$GUEST_ADDR."

# --- Step 4: escape attempts (the actual exit gate) ---------------------
# Run for real, from this script, against the still-live session -- not
# printed as instructions for a human to type into a second terminal
# before teardown races ahead. An earlier version of this script did
# exactly that, and the session was gone by the time anyone could act on
# it: the checkboxes below stayed unchecked because there was never a
# window in which to actually run anything. Capturing real output here,
# from both sides, is what makes this the real verification rather than
# "looks correct from inspection" (AGENTS.md Section 3).
say "Step 4: escape attempts from inside the guest"

# 1. Host files: a marker with a random, single-run token the guest has
# no legitimate way to know in advance -- proves there is no shared
# filesystem to find it on, not just that one specific path is empty.
HOST_MARKER="$LOG_DIR/host-marker-$$"
HOST_TOKEN="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
echo "$HOST_TOKEN" > "$HOST_MARKER"
GUEST_FILE_OUTPUT="$(ssh "${SSH_OPTS[@]}" "habitat@$GUEST_ADDR" "cat '$HOST_MARKER' 2>&1 || echo BLOCKED")"
record ""
record "- Host files: wrote a random token to $HOST_MARKER on the host, then ran"
record "  \`ssh habitat@$GUEST_ADDR cat '$HOST_MARKER'\` from the host into the guest."
record "  Guest saw: \`$GUEST_FILE_OUTPUT\`"
if [[ "$GUEST_FILE_OUTPUT" == *"$HOST_TOKEN"* ]]; then
    record "  **FAILED**: the guest read the host's own file -- a shared filesystem path exists."
else
    record "  CONFIRMED BLOCKED: the guest could not read the host's file."
fi
rm -f "$HOST_MARKER"

# 2. Host processes: capture this shell's own PID (a process that only
# exists in the host's process table) and confirm it's absent from what
# the guest sees.
HOST_PID="$$"
GUEST_PS_OUTPUT="$(ssh "${SSH_OPTS[@]}" "habitat@$GUEST_ADDR" 'ps aux 2>&1 || echo BLOCKED')"
record ""
record "- Host processes: this script's own host PID is $HOST_PID. Guest's \`ps aux\`:"
record '```'
record "$GUEST_PS_OUTPUT"
record '```'
if echo "$GUEST_PS_OUTPUT" | grep -qw "$HOST_PID"; then
    record "  **FAILED**: the host's PID $HOST_PID is visible inside the guest's process table."
else
    record "  CONFIRMED BLOCKED: the host's PID is not visible inside the guest."
fi

# 3. Host network namespace: capture the host's real routing table and
# the guest's, side by side -- the guest must not show the host's actual
# routes/interfaces.
HOST_ROUTE_OUTPUT="$(ip route 2>&1 || echo "(ip route unavailable on host)")"
GUEST_ROUTE_OUTPUT="$(ssh "${SSH_OPTS[@]}" "habitat@$GUEST_ADDR" 'ip route 2>&1 || echo BLOCKED')"
record ""
record "- Host network namespace. Host's \`ip route\`:"
record '```'
record "$HOST_ROUTE_OUTPUT"
record '```'
record "  Guest's \`ip route\`:"
record '```'
record "$GUEST_ROUTE_OUTPUT"
record '```'
record ""
record "MANUAL: compare the two route tables above by eye -- the guest's must be its own"
record "minimal virtual network, never the host's real routes/gateway/interfaces. This one"
record "needs a human judgment call, not a substring match."
record ""
record "- [ ] Host files unreachable (see automated result above)"
record "- [ ] Host processes unreachable (see automated result above)"
record "- [ ] Host network namespace shows no host routes (compare the two tables above)"

# --- Step 5: teardown -----------------------------------------------------
say "Step 5: teardown"
set +e
podman rm --force --ignore "$SESSION_NAME" > "$LOG_DIR/teardown.log" 2>&1
TEARDOWN_EXIT=$?
set -e
rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
record "- Teardown exit: $TEARDOWN_EXIT (log: $LOG_DIR/teardown.log)"
if podman ps -a --format '{{.Names}}' | grep -qx "$SESSION_NAME"; then
    record "- **FAILED**: container still listed in \`podman ps -a\` after teardown."
    exit 1
fi
if [[ -e "$WORKSPACE_DISK" ]]; then
    record "- **FAILED**: workspace disk still present after teardown."
    exit 1
fi
if [[ -e "$SSH_KEY_PATH" || -e "$SSH_KEY_PATH.pub" ]]; then
    record "- **FAILED**: session SSH key still present after teardown."
    exit 1
fi
record "- CONFIRMED: no residual container, disk image, or SSH key after teardown."

say "Done"
echo "Summary written to $SUMMARY -- Step 4's file/process checks ran automatically and are"
echo "recorded above; only the network-route comparison and the final checkboxes need a human look."
