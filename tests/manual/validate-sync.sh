#!/usr/bin/env bash
# tests/manual/validate-sync.sh
#
# Phase 4's real-hardware exit gate (tmp/wip/implementation-plan.md): "a
# live-session process inventory confirms no continuous/background sync
# daemon exists beyond the two discrete invocations." Neither this dev
# container nor this project's CI (ubuntu-latest, no nested
# virtualization) has real KVM, so this is a manual, host-dependent
# runbook, not a `cargo test` target -- see tests/manual/README.md.
#
# Everything else in Phase 4's exit gate (malformed/corrupted patches
# flagged not applied, a smuggled blocklisted file caught by the
# re-check, the no-op short-circuit, sync latency/throughput against
# real fixtures) is covered by real, automated tests already:
#   tests/unit/workspace/sync_exit_gate.rs
#   tests/adversarial/sync_patch_validation.rs
# This script's only job is the one thing those can't cover without a
# real, booted guest: proving there is no background process bridging
# host and sandbox, only the two discrete sync invocations
# (habitat_workspace::sync::sync_host_to_sandbox /
# sync_sandbox_to_host) actually running when they're supposed to and
# nothing running in between.
#
# Steps 4-5 run for real, from this script, against the still-live
# session -- not printed as instructions for a human to act on in a
# second terminal before teardown races ahead. An earlier version of this
# script did exactly that (the same mistake an earlier version of
# `validate-vm-launch.sh` made for its own Step 4, see that script's
# history) -- teardown ran immediately after printing the instructions,
# so there was never a window to actually act on them. `habitat run`
# doesn't wire up the sync calls yet (Phase 7 territory), so this script
# drives `crates/workspace/examples/manual_sync_round.rs`, a small example
# binary that exists solely for this runbook and makes one real,
# discrete `sync_host_to_sandbox`/`sync_sandbox_to_host` call against a
# real guest.
#
# **Guest exec channel is SSH, not `podman exec`, reached by published
# port, not a distinct guest IP** (docs/decisions/0008-guest-exec-channel.md):
# a real run against `validate-vm-launch.sh` confirmed `podman exec` does
# not work against the `krun` runtime at all, and that `pasta` gives no
# separate, `podman inspect`-visible guest IP either -- reachability is
# an explicitly published port on `127.0.0.1`, resolved via `podman
# port`. This script generates its own throwaway session keypair and
# resolves the published port, exactly as `habitat_vm::launcher` does.
#
# Requires: an AlmaLinux/Fedora host (dnf-family) with Podman + crun-krun
# installed and /dev/kvm exposed -- i.e. a host that already passes
# tests/manual/validate-real-hardware.sh and validate-vm-launch.sh.
#
# Usage:
#   tests/manual/validate-sync.sh              # run the full pass
#   tests/manual/validate-sync.sh --report-only # print a prior run's summary

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$REPO_ROOT/tmp/wip/sync-validation"
SESSION_NAME="habitat-manual-sync-$$"
GUEST_IMAGE="${HABITAT_GUEST_IMAGE:-localhost/habitat-guest:alpine}"
GUEST_WORKSPACE_DIR="/workspace"
WORKSPACE_DISK="$LOG_DIR/session.img"
ANNOTATION_KEY="io.habitat.vm.workspace-disk"
SSH_KEY_PATH="$LOG_DIR/session-key"
GUEST_SSH_HOST="127.0.0.1"

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

record "# Sync validation run -- $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
record ""
record "Host: $(uname -a)"
record ""

# --- Step 1: host suitability -------------------------------------------
say "Step 1: host suitability"
if [[ ! -e /dev/kvm ]]; then
    fail "This host has no /dev/kvm -- run tests/manual/validate-real-hardware.sh first."
    record "- **ABORTED**: no /dev/kvm on this host."
    exit 1
fi
for bin in podman ssh ssh-keygen; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        fail "$bin not found on PATH."
        record "- **ABORTED**: $bin not installed."
        exit 1
    fi
done
record "- /dev/kvm: present"
record "- podman: $(podman --version)"

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

rm -f "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_PATH" -C habitat-session -q
AUTHORIZED_KEY="$(cat "$SSH_KEY_PATH.pub")"
record "- Generated a fresh session SSH keypair at $SSH_KEY_PATH"

# --- Step 2: launch a real session --------------------------------------
say "Step 2: launch a real session to sync against"
dd if=/dev/zero of="$WORKSPACE_DISK" bs=1M count=64 status=none
mkfs.ext4 -q -F "$WORKSPACE_DISK"
podman run --detach --rm --name "$SESSION_NAME" \
    --runtime krun --network "pasta:--map-host-loopback=169.254.1.1" --dns 169.254.1.1 \
    --annotation "krun.use_passt=1" \
    --cpus 2 --memory 2048m \
    --annotation "${ANNOTATION_KEY}=${WORKSPACE_DISK}" \
    --env "HABITAT_AUTHORIZED_KEY=${AUTHORIZED_KEY}" \
    --publish "${GUEST_SSH_HOST}::22/tcp" \
    "$GUEST_IMAGE" > "$LOG_DIR/launch.log" 2>&1
record "- Launched session $SESSION_NAME (log: $LOG_DIR/launch.log)"

PORT_OUTPUT="$(podman port "$SESSION_NAME" 22/tcp 2>&1 || true)"
GUEST_SSH_PORT="${PORT_OUTPUT##*:}"
record "- \`podman port $SESSION_NAME 22/tcp\` -> \`$PORT_OUTPUT\` (port: $GUEST_SSH_PORT)"

SSH_OPTS=(-i "$SSH_KEY_PATH" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes -p "$GUEST_SSH_PORT")

for _ in $(seq 1 30); do
    if ssh "${SSH_OPTS[@]}" "habitat@$GUEST_SSH_HOST" true 2>/dev/null; then
        break
    fi
    sleep 1
done

ssh "${SSH_OPTS[@]}" "habitat@$GUEST_SSH_HOST" "git init --quiet '$GUEST_WORKSPACE_DIR'" || true
record "- Seeded a git repo at $GUEST_WORKSPACE_DIR inside the guest (over SSH)"

# --- Step 3: baseline process inventory (idle, between syncs) -----------
say "Step 3: baseline process inventory -- idle, no sync in progress"
BASELINE="$LOG_DIR/ps-baseline.txt"
ps -eo pid,ppid,cmd --no-headers | grep -iE '[p]odman|[h]abitat|[s]sh|[s]cp' | grep -v "$$" > "$BASELINE" || true
record "- Baseline process snapshot written to $BASELINE"
record '```'
cat "$BASELINE" | tee -a "$SUMMARY"
record '```'

# --- Steps 4-5: real sync rounds, each immediately re-inventoried -------
STATE_DIR="$LOG_DIR/sync-state"
rm -rf "$STATE_DIR"
mkdir -p "$STATE_DIR"

# Runs one sync round for real via the manual_sync_round example, then
# immediately re-inventories processes and compares against the idle
# baseline -- exactly the check an earlier version of this script left
# for a human to do by hand in a race against teardown.
run_sync_round() {
    local step_label="$1" direction="$2" checklist_label="$3"
    say "$step_label: $direction sync (one discrete invocation) then re-check"
    record ""
    set +e
    SYNC_OUTPUT="$(cd "$REPO_ROOT" && cargo run --quiet -p habitat-workspace --example manual_sync_round -- \
        "$direction" "$GUEST_SSH_HOST" "$GUEST_SSH_PORT" "$SSH_KEY_PATH" "$STATE_DIR" 2>&1)"
    SYNC_EXIT=$?
    set -e
    record "- \`manual_sync_round $direction\` (exit $SYNC_EXIT): \`$SYNC_OUTPUT\`"
    AFTER="$(ps -eo pid,ppid,cmd --no-headers | grep -iE '[p]odman|[h]abitat|[s]sh|[s]cp' | grep -v "$$" || true)"
    if [[ "$AFTER" == "$(cat "$BASELINE")" ]]; then
        record "  CONFIRMED: process list after this round matches the idle baseline."
        record "- [x] $checklist_label"
    else
        record "  **FAILED**: process list after this round differs from the idle baseline:"
        record '```'
        record "$AFTER"
        record '```'
        record "- [ ] $checklist_label"
    fi
}

run_sync_round "Step 4" "host-to-sandbox" "Process list after a host->sandbox sync round matches the idle baseline"
run_sync_round "Step 5" "sandbox-to-host" "Process list after a sandbox->host sync round matches the idle baseline"

# --- Aggregate check: several rounds back-to-back, re-inventoried after
# each one -- the exit gate's actual claim is about the whole sequence,
# not just one round in each direction.
say "Step 5b: aggregate check -- several rounds back-to-back"
record ""
AGGREGATE_OK=1
for round in 1 2; do
    run_sync_round "Step 5b round $round (host->sandbox)" "host-to-sandbox" "round $round host->sandbox matches baseline"
    [[ "$AFTER" == "$(cat "$BASELINE")" ]] || AGGREGATE_OK=0
    run_sync_round "Step 5b round $round (sandbox->host)" "sandbox-to-host" "round $round sandbox->host matches baseline"
    [[ "$AFTER" == "$(cat "$BASELINE")" ]] || AGGREGATE_OK=0
done
if [[ "$AGGREGATE_OK" -eq 1 ]]; then
    record "- [x] No continuous/background sync process observed across multiple rounds"
else
    record "- [ ] No continuous/background sync process observed across multiple rounds"
fi

# --- Step 6: teardown -----------------------------------------------------
say "Step 6: teardown"
podman rm --force --ignore "$SESSION_NAME" > "$LOG_DIR/teardown.log" 2>&1 || true
rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
record ""
record "- Session torn down; workspace disk and session SSH key removed."

say "Done"
echo "Summary written to $SUMMARY -- fold Steps 4-5's manual results into it by hand."
