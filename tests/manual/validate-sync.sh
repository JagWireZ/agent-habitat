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
    --runtime krun --network pasta --dns 127.0.0.1 --cpus 2 --memory 2048m \
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
ps -eo pid,ppid,cmd --no-headers | grep -iE 'podman|habitat|ssh|scp' | grep -v "$$" > "$BASELINE" || true
record "- Baseline process snapshot written to $BASELINE"
record '```'
cat "$BASELINE" | tee -a "$SUMMARY"
record '```'

# --- Step 4: run a host->sandbox sync round and re-inventory ------------
say "Step 4: host->sandbox sync (one discrete invocation) then re-check"
record ""
record "MANUAL: run one host->sandbox sync round here (e.g. via a debug binary or"
record "\`cargo run\` invocation that calls habitat_workspace::sync::sync_host_to_sandbox"
record "against session $SESSION_NAME at $GUEST_SSH_HOST:$GUEST_SSH_PORT using $SSH_KEY_PATH), then"
record "immediately re-run:"
record '```'
record "ps -eo pid,ppid,cmd --no-headers | grep -iE 'podman|habitat|ssh|scp' | grep -v \$\$"
record '```'
record "and confirm the resulting process list matches the baseline above once the sync"
record "round has returned -- no leftover \`ssh\`/\`scp\` process, no new long-lived process"
record "of any kind still running."
record ""
record "- [ ] Process list after a host->sandbox sync round matches the idle baseline"

# --- Step 5: run a sandbox->host sync round and re-inventory ------------
say "Step 5: sandbox->host sync (one discrete invocation) then re-check"
record ""
record "MANUAL: same as Step 4, but for sync_sandbox_to_host. Confirm the process list"
record "again matches the idle baseline once the round has returned."
record ""
record "- [ ] Process list after a sandbox->host sync round matches the idle baseline"
record ""
record "MANUAL: also confirm the *aggregate* claim this whole exit gate is about: across"
record "several rounds of both sync directions run back-to-back, at no point does a"
record "process inventory show anything beyond the two discrete invocations plus whatever"
record "they call inside a normal invocation's lifetime (git, ssh, scp) -- no persistent"
record "watcher, poller, or background bridge process appears at any point between rounds."
record ""
record "- [ ] No continuous/background sync process observed across multiple rounds"

# --- Step 6: teardown -----------------------------------------------------
say "Step 6: teardown"
podman rm --force --ignore "$SESSION_NAME" > "$LOG_DIR/teardown.log" 2>&1 || true
rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
record ""
record "- Session torn down; workspace disk and session SSH key removed."

say "Done"
echo "Summary written to $SUMMARY -- fold Steps 4-5's manual results into it by hand."
