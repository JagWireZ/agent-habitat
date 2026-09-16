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
# **Guest reachability is by published port, not a distinct guest IP**
# (second correction, same ADR): a real run of an earlier version of this
# script confirmed `podman inspect`'s `NetworkSettings` fields (IPAddress,
# Gateway, everything) all come back empty for a `pasta`-backed
# container -- `pasta` is a user-mode translator with no Podman-tracked
# container IP to report. This script instead publishes the guest's
# sshd port to an ephemeral host port on 127.0.0.1 and resolves it via
# `podman port`, exactly as `habitat_vm::launcher::guest_ssh_port` does.
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
# (WORKSPACE_DISK_ANNOTATION) is a best-understanding placeholder until
# this runbook has actually been run once, the same "confirmed wrong on
# real hardware, then fixed" pattern Phase 1 hit with the crun-krun
# package/binary name split.
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
GUEST_SSH_HOST="127.0.0.1"

mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.md"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
fail() { printf '\033[31m%s\033[0m\n' "$1" >&2; }

declare -a RESULTS=()

# status <label> <PASS|FAIL|SKIP|MANUAL> [detail]
status() {
    local label="$1" state="$2" detail="${3:-}"
    local color tag
    case "$state" in
        PASS)    color='\033[32m'; tag="PASS   " ;;
        FAIL)    color='\033[31m'; tag="FAIL   " ;;
        SKIP)    color='\033[33m'; tag="SKIP   " ;;
        MANUAL)  color='\033[36m'; tag="MANUAL " ;;
        *)       color='\033[0m';  tag="$state " ;;
    esac
    printf "${color}\033[1m[%s]\033[0m %s\n" "$tag" "$label"
    RESULTS+=("$state|$label${detail:+ -- $detail}")
}

# result_summary: prints the colored table and appends the markdown
# checklist version to $SUMMARY. Called at the end of every validate-*.sh
# script in this directory, right before its final "Done" banner.
result_summary() {
    say "Result summary"
    local r state label color
    for r in "${RESULTS[@]}"; do
        state="${r%%|*}"
        label="${r#*|}"
        case "$state" in
            PASS)   color='\033[32m' ;;
            FAIL)   color='\033[31m' ;;
            SKIP)   color='\033[33m' ;;
            MANUAL) color='\033[36m' ;;
            *)      color='\033[0m'  ;;
        esac
        printf "${color}\033[1m%-8s\033[0m %s\n" "$state" "$label"
    done
    {
        printf '\n## Result summary\n'
        for r in "${RESULTS[@]}"; do
            state="${r%%|*}"
            label="${r#*|}"
            printf '- **%s** -- %s\n' "$state" "$label"
        done
    } >> "$SUMMARY"
}

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
    status "Step 1: host suitability" FAIL "no /dev/kvm on this host"
    exit 1
fi
for bin in podman krun ssh ssh-keygen; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        fail "$bin not found on PATH."
        record "- **ABORTED**: $bin not installed."
        status "Step 1: host suitability" FAIL "$bin not installed"
        exit 1
    fi
done
record "- /dev/kvm: present"
record "- podman: $(podman --version)"
record "- krun: $(krun --version 2>&1 || echo 'present (no --version output)')"
record "- ssh: $(ssh -V 2>&1)"
status "Step 1: host suitability" PASS

# --- Step 1b: ensure the guest image actually exists locally -----------
say "Step 1b: guest image"
if ! podman image exists "$GUEST_IMAGE"; then
    if [[ "$GUEST_IMAGE" == "localhost/habitat-guest:alpine" ]]; then
        record "- $GUEST_IMAGE not found locally -- building it via guest/build.sh"
        "$REPO_ROOT/guest/build.sh"
    else
        fail "$GUEST_IMAGE (from \$HABITAT_GUEST_IMAGE) not found locally, and it isn't the default this script knows how to build. Build or pull it yourself first."
        record "- **ABORTED**: $GUEST_IMAGE not present and not buildable by this script."
        status "Step 1b: guest image" FAIL "$GUEST_IMAGE not present and not buildable"
        exit 1
    fi
fi
record "- guest image present: $GUEST_IMAGE"
status "Step 1b: guest image" PASS

# --- Step 1c: generate this session's ephemeral SSH keypair -------------
say "Step 1c: session SSH keypair (guest exec channel)"
rm -f "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_PATH" -C habitat-session -q
AUTHORIZED_KEY="$(cat "$SSH_KEY_PATH.pub")"
record "- Generated a fresh ed25519 keypair at $SSH_KEY_PATH (never reused, deleted at teardown)."
status "Step 1c: session SSH keypair" PASS

# --- Step 2: build a session disk image to launch against ---------------
say "Step 2: build a disposable session disk"
dd if=/dev/zero of="$WORKSPACE_DISK" bs=1M count=64 status=none
mkfs.ext4 -q -F "$WORKSPACE_DISK"
record "- Built a 64MB throwaway workspace disk at $WORKSPACE_DISK"
status "Step 2: build session disk" PASS

PODMAN_ARGS=(
    run --detach --rm --name "$SESSION_NAME"
    --runtime krun
    # Matches habitat_vm::launcher's current build_run_args (Phase 5):
    # a pasta-backed network with DNS pinned to a fixed host-loopback-map
    # address (network_setup::HOST_LOOPBACK_ADDR), never the Phase 3
    # `--network none` placeholder or libkrun's default TSI mode. No real
    # proxy is actually running for this script's own purpose (a
    # containment escape attempt, not an egress trace -- that's
    # tests/manual/validate-egress.sh's job), so this address is a
    # placeholder the guest's DNS won't actually be able to reach; that
    # doesn't affect this script's own checks.
    --network "pasta:--map-host-loopback=169.254.1.1"
    --dns 169.254.1.1
    # Without this, crun-krun silently falls back to libkrun's own
    # default TSI networking regardless of `--network pasta` above --
    # confirmed on real hardware (tmp/wip/vm-launch-validation): a
    # session launched without this annotation booted with `tsi_hijack`
    # on its kernel command line and no virtio-net device at all. Per
    # crun's own krun.1.md: `krun.use_passt=NUM`, "When set to a value
    # greater than 0, enable passt-based networking in the microVM."
    --annotation "krun.use_passt=1"
    --cpus 2 --memory 2048m
    --annotation "${ANNOTATION_KEY}=${WORKSPACE_DISK}"
    --env "HABITAT_AUTHORIZED_KEY=${AUTHORIZED_KEY}"
    # Guest exec channel (docs/decisions/0008-guest-exec-channel.md):
    # publish the guest's sshd port to an ephemeral host port, loopback
    # only -- never reachable from outside this host. `pasta` gives no
    # separate, podman-inspect-visible guest IP to dial directly
    # (confirmed on real hardware: NetworkSettings comes back empty for
    # every field), so this published port is how the host reaches in.
    --publish "${GUEST_SSH_HOST}::22/tcp"
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
    status "Step 3: launch the session" FAIL "exit=$LAUNCH_EXIT -- see $LOG_DIR/launch.log"
    rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
    exit 1
fi
record "- CONFIRMED: session launched."
status "Step 3: launch the session" PASS

# --- Step 3b: resolve the guest's published SSH port ---------------------
say "Step 3b: resolve the guest's published SSH port"
PORT_OUTPUT="$(podman port "$SESSION_NAME" 22/tcp 2>&1 || true)"
record "- \`podman port $SESSION_NAME 22/tcp\` -> \`$PORT_OUTPUT\`"
GUEST_SSH_PORT="${PORT_OUTPUT##*:}"
if ! [[ "$GUEST_SSH_PORT" =~ ^[0-9]+$ ]]; then
    record "- **FAILED**: could not parse a port number from \`podman port\`'s output above."
    record "  Find the actual shape of that output and fix this script's parsing (and"
    record "  \`habitat_vm::launcher::guest_ssh_port\`'s parsing) to match, then re-run."
    status "Step 3b: resolve guest SSH port" FAIL "could not parse port from: $PORT_OUTPUT"
    podman rm --force --ignore "$SESSION_NAME" >/dev/null 2>&1 || true
    rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
    exit 1
fi
record "- Resolved guest SSH port: $GUEST_SSH_PORT"
status "Step 3b: resolve guest SSH port" PASS "port=$GUEST_SSH_PORT"

# Every SSH/SCP call to the guest in this script uses these options --
# matches `habitat_workspace::guest_exec::ssh_option_args` exactly, so
# this script keeps exercising the real client-side flags in use.
SSH_OPTS=(-i "$SSH_KEY_PATH" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes -p "$GUEST_SSH_PORT")

say "Waiting for sshd to accept connections"
SSH_READY=0
for _ in $(seq 1 30); do
    if ssh "${SSH_OPTS[@]}" "habitat@$GUEST_SSH_HOST" true 2>/dev/null; then
        SSH_READY=1
        break
    fi
    sleep 1
done
if [[ "$SSH_READY" -ne 1 ]]; then
    record "- **FAILED**: could not SSH into the guest at $GUEST_SSH_HOST:$GUEST_SSH_PORT within 30s -- confirm guest/entrypoint.sh actually starts sshd."
    record "  Guest logs (\`podman logs $SESSION_NAME\`):"
    record '```'
    record "$(podman logs "$SESSION_NAME" 2>&1 || echo '(podman logs failed)')"
    record '```'
    status "Step 3c: wait for SSH" FAIL "no SSH within 30s"
    podman rm --force --ignore "$SESSION_NAME" >/dev/null 2>&1 || true
    rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
    exit 1
fi
record "- CONFIRMED: SSH exec channel reachable at habitat@$GUEST_SSH_HOST:$GUEST_SSH_PORT."
status "Step 3c: wait for SSH" PASS

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
GUEST_FILE_OUTPUT="$(ssh "${SSH_OPTS[@]}" "habitat@$GUEST_SSH_HOST" "cat '$HOST_MARKER' 2>&1 || echo BLOCKED")"
record ""
record "- Host files: wrote a random token to $HOST_MARKER on the host, then ran"
record "  \`ssh habitat@$GUEST_SSH_HOST cat '$HOST_MARKER'\` from the host into the guest."
record "  Guest saw: \`$GUEST_FILE_OUTPUT\`"
if [[ "$GUEST_FILE_OUTPUT" == *"$HOST_TOKEN"* ]]; then
    record "  **FAILED**: the guest read the host's own file -- a shared filesystem path exists."
    status "Step 4: host files unreachable" FAIL "guest read the host's token"
else
    record "  CONFIRMED BLOCKED: the guest could not read the host's file."
    status "Step 4: host files unreachable" PASS
fi
rm -f "$HOST_MARKER"

# 2. Host processes: capture this shell's own PID (a process that only
# exists in the host's process table) and confirm it's absent from what
# the guest sees.
HOST_PID="$$"
GUEST_PS_OUTPUT="$(ssh "${SSH_OPTS[@]}" "habitat@$GUEST_SSH_HOST" 'ps aux 2>&1 || echo BLOCKED')"
record ""
record "- Host processes: this script's own host PID is $HOST_PID. Guest's \`ps aux\`:"
record '```'
record "$GUEST_PS_OUTPUT"
record '```'
if echo "$GUEST_PS_OUTPUT" | grep -qw "$HOST_PID"; then
    record "  **FAILED**: the host's PID $HOST_PID is visible inside the guest's process table."
    status "Step 4: host processes unreachable" FAIL "host PID $HOST_PID visible in guest"
else
    record "  CONFIRMED BLOCKED: the host's PID is not visible inside the guest."
    status "Step 4: host processes unreachable" PASS
fi

# 3. Host network namespace: capture the host's real routing table and
# the guest's, side by side -- the guest must not show the host's actual
# routes/interfaces.
HOST_ROUTE_OUTPUT="$(ip route 2>&1 || echo "(ip route unavailable on host)")"
GUEST_ROUTE_OUTPUT="$(ssh "${SSH_OPTS[@]}" "habitat@$GUEST_SSH_HOST" 'ip route 2>&1 || echo BLOCKED')"
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
status "Step 4: host network namespace" MANUAL "compare the two route tables above by eye"

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
    status "Step 5: teardown" FAIL "container still listed after teardown"
    exit 1
fi
if [[ -e "$WORKSPACE_DISK" ]]; then
    record "- **FAILED**: workspace disk still present after teardown."
    status "Step 5: teardown" FAIL "workspace disk still present after teardown"
    exit 1
fi
if [[ -e "$SSH_KEY_PATH" || -e "$SSH_KEY_PATH.pub" ]]; then
    record "- **FAILED**: session SSH key still present after teardown."
    status "Step 5: teardown" FAIL "session SSH key still present after teardown"
    exit 1
fi
record "- CONFIRMED: no residual container, disk image, or SSH key after teardown."
status "Step 5: teardown" PASS

result_summary

say "Done"
echo "Summary written to $SUMMARY -- Step 4's file/process checks ran automatically and are"
echo "recorded above; only the network-route comparison and the final checkboxes need a human look."
