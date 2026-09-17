#!/usr/bin/env bash
# tests/manual/vm-session.sh
#
# Ad-hoc companion to validate-egress.sh: starts a single long-lived
# session (proxy/DNS harness + pasta-backed guest) that stays up across
# separate invocations of this script, so a real host can be poked at
# interactively -- `ip link`, direct `curl` probes against
# HOST_LOOPBACK_ADDR, manual `nft` inspection -- without re-running the
# full validate-egress.sh pass (which tears everything down at the end of
# a single run) for every single command.
#
# State (session name, SSH key path, guest SSH port, harness PID) is
# persisted to $LOG_DIR/state.env between invocations, since `start` and
# a later `exec`/`stop` are separate script runs, not one script instance.
#
# Usage:
#   tests/manual/vm-session.sh start [--no-harness]
#   tests/manual/vm-session.sh exec <command...>   # run over SSH in the guest
#   tests/manual/vm-session.sh ssh                 # interactive shell in the guest
#   tests/manual/vm-session.sh netns <command...>  # run on the HOST inside the
#                                                   # guest's own netns+userns
#                                                   # (nsenter, no elevated
#                                                   # privilege -- see Step 4's
#                                                   # own note in validate-egress.sh)
#   tests/manual/vm-session.sh status
#   tests/manual/vm-session.sh stop
#
# Same constants as validate-egress.sh (PASTA_NETWORK_MODE,
# HOST_LOOPBACK_ADDR, PROXY_ADDR, DNS_ADDR) -- kept in sync by hand with
# crates/egress/src/network_setup.rs, same tradeoff that script already
# makes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$REPO_ROOT/tmp/wip/vm-session"
STATE_FILE="$LOG_DIR/state.env"
GUEST_IMAGE="${HABITAT_GUEST_IMAGE:-localhost/habitat-guest:alpine}"
WORKSPACE_DISK="$LOG_DIR/session.img"
SSH_KEY_PATH="$LOG_DIR/session-key"
GUEST_SSH_HOST="127.0.0.1"
PROXY_ADDR="127.0.0.1:8443"
DNS_ADDR="127.0.0.1:53"
PASTA_NETWORK_MODE="pasta"
HOST_LOOPBACK_ADDR="169.254.1.1"
AUDIT_LOG="$LOG_DIR/audit.jsonl"
HARNESS_LOG="$LOG_DIR/egress-harness.log"

mkdir -p "$LOG_DIR"

fail() { printf '\033[31m%s\033[0m\n' "$1" >&2; }
info() { printf '\033[1m%s\033[0m\n' "$1"; }

load_state() {
    if [[ -f "$STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$STATE_FILE"
    fi
}

save_state() {
    cat > "$STATE_FILE" <<EOF
SESSION_NAME="${SESSION_NAME:-}"
GUEST_SSH_PORT="${GUEST_SSH_PORT:-}"
HARNESS_PID="${HARNESS_PID:-}"
EOF
}

running() {
    load_state
    [[ -n "${SESSION_NAME:-}" ]] && podman inspect "$SESSION_NAME" >/dev/null 2>&1
}

ssh_opts() {
    load_state
    echo -i "$SSH_KEY_PATH" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes -p "$GUEST_SSH_PORT"
}

cmd_start() {
    if running; then
        fail "A session is already up (\`$SESSION_NAME\`) -- run \`stop\` first."
        exit 1
    fi

    local with_harness=1
    if [[ "${1:-}" == "--no-harness" ]]; then
        with_harness=""
    fi

    if [[ ! -e /dev/kvm ]]; then
        fail "No /dev/kvm on this host."
        exit 1
    fi
    for bin in podman krun passt nft nsenter ssh ssh-keygen; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            fail "$bin not found on PATH."
            exit 1
        fi
    done
    if ! podman image exists "$GUEST_IMAGE"; then
        if [[ "$GUEST_IMAGE" == "localhost/habitat-guest:alpine" ]]; then
            info "Building $GUEST_IMAGE via guest/build.sh..."
            "$REPO_ROOT/guest/build.sh"
        else
            fail "$GUEST_IMAGE not found locally, and it isn't the default this script can build."
            exit 1
        fi
    fi

    HARNESS_PID=""
    if [[ -n "$with_harness" ]]; then
        info "Building and starting the egress proxy/DNS harness..."
        cargo build --quiet -p habitat-egress --example egress_harness --example print_firewall_rules
        local harness_bin="$REPO_ROOT/target/debug/examples/egress_harness"
        local harness_args=(--proxy-addr "$PROXY_ADDR" --dns-addr "$DNS_ADDR" --audit-log "$AUDIT_LOG")
        if [[ -n "${HABITAT_PROJECT_CONFIG:-}" ]]; then
            harness_args+=(--project-config "$HABITAT_PROJECT_CONFIG")
        fi
        : > "$HARNESS_LOG"
        "$harness_bin" "${harness_args[@]}" >> "$HARNESS_LOG" 2>&1 &
        HARNESS_PID=$!

        local ready=""
        for _ in $(seq 1 60); do
            if ! kill -0 "$HARNESS_PID" 2>/dev/null; then
                break
            fi
            if grep -q '^READY' "$HARNESS_LOG" 2>/dev/null; then
                ready=1
                break
            fi
            sleep 0.5
        done
        if [[ -z "$ready" ]]; then
            if grep -qi 'bind: permission denied' "$HARNESS_LOG" 2>/dev/null && [[ -t 0 ]] && command -v setcap >/dev/null 2>&1; then
                fail "Binding on port 53 needs CAP_NET_BIND_SERVICE."
                read -r -p "Grant it to $harness_bin via 'sudo setcap cap_net_bind_service=+ep' now? [y/N] " reply
                if [[ "$reply" =~ ^[Yy]$ ]] && sudo setcap cap_net_bind_service=+ep "$harness_bin"; then
                    : > "$HARNESS_LOG"
                    "$harness_bin" "${harness_args[@]}" >> "$HARNESS_LOG" 2>&1 &
                    HARNESS_PID=$!
                    for _ in $(seq 1 60); do
                        if grep -q '^READY' "$HARNESS_LOG" 2>/dev/null; then
                            ready=1
                            break
                        fi
                        sleep 0.5
                    done
                fi
            fi
        fi
        if [[ -z "$ready" ]]; then
            fail "egress_harness did not report READY -- see $HARNESS_LOG"
            cat "$HARNESS_LOG" >&2
            kill "$HARNESS_PID" 2>/dev/null || true
            exit 1
        fi
        info "Harness ready: $(grep '^READY' "$HARNESS_LOG")"
    fi

    SESSION_NAME="habitat-manual-vm-$$"
    dd if=/dev/zero of="$WORKSPACE_DISK" bs=1M count=64 status=none
    mkfs.ext4 -q -F "$WORKSPACE_DISK"

    rm -f "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
    ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_PATH" -C habitat-session -q
    local authorized_key
    authorized_key="$(cat "$SSH_KEY_PATH.pub")"

    local podman_args=(
        run --detach --rm --name "$SESSION_NAME"
        --runtime krun
        --network "${PASTA_NETWORK_MODE}:--map-host-loopback=${HOST_LOOPBACK_ADDR}"
        --dns "$HOST_LOOPBACK_ADDR"
        --annotation "krun.use_passt=1"
        --cpus 2 --memory 2048m
        --annotation "io.habitat.vm.workspace-disk=${WORKSPACE_DISK}"
        --env "HABITAT_AUTHORIZED_KEY=${authorized_key}"
        --publish "${GUEST_SSH_HOST}::2222/tcp"
        "$GUEST_IMAGE"
    )

    info "Launching $SESSION_NAME..."
    if ! podman "${podman_args[@]}" > "$LOG_DIR/launch.log" 2>&1; then
        cat "$LOG_DIR/launch.log" >&2
        fail "Launch failed -- see $LOG_DIR/launch.log"
        if [[ -n "$HARNESS_PID" ]]; then
            kill "$HARNESS_PID" 2>/dev/null || true
        fi
        rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
        exit 1
    fi

    local port_output
    port_output="$(podman port "$SESSION_NAME" 2222/tcp 2>&1 || true)"
    GUEST_SSH_PORT="${port_output##*:}"
    save_state

    info "Waiting for SSH..."
    local opts
    opts=($(ssh_opts))
    for _ in $(seq 1 30); do
        if ssh "${opts[@]}" "habitat@$GUEST_SSH_HOST" true 2>/dev/null; then
            break
        fi
        sleep 1
    done

    local container_pid
    container_pid="$(podman inspect --format '{{.State.Pid}}' "$SESSION_NAME")"
    info "Session up: name=$SESSION_NAME pid=$container_pid ssh_port=$GUEST_SSH_PORT"
    info "  exec: tests/manual/vm-session.sh exec <command>"
    info "  ssh:  tests/manual/vm-session.sh ssh"
    info "  netns (host-side, in the guest's netns): tests/manual/vm-session.sh netns <command>"
    info "  stop: tests/manual/vm-session.sh stop"
}

cmd_exec() {
    if ! running; then
        fail "No session is up -- run \`start\` first."
        exit 1
    fi
    if [[ $# -eq 0 ]]; then
        fail "Usage: $0 exec <command...>"
        exit 1
    fi
    local opts
    opts=($(ssh_opts))
    # `-tt` forces a remote PTY even though this call has no local one --
    # without it, a remote program like `curl -v` sees a non-tty stderr and
    # fully block-buffers its output instead of flushing per line, so a
    # genuinely hung connection (nft's `drop` policy sends no RST/ICMP,
    # curl can sit past its own `-m` alarm on some code paths) shows
    # nothing at all until the process exits -- indistinguishable from
    # this wrapper's own `timeout` silently killing it first. A PTY makes
    # `curl -v` line-buffer instead, so partial output streams live even
    # if the command is later killed.
    timeout 15 ssh -tt "${opts[@]}" "habitat@$GUEST_SSH_HOST" "$*"
}

cmd_ssh() {
    if ! running; then
        fail "No session is up -- run \`start\` first."
        exit 1
    fi
    local opts
    opts=($(ssh_opts))
    ssh "${opts[@]}" "habitat@$GUEST_SSH_HOST"
}

cmd_netns() {
    if ! running; then
        fail "No session is up -- run \`start\` first."
        exit 1
    fi
    if [[ $# -eq 0 ]]; then
        fail "Usage: $0 netns <command...>"
        exit 1
    fi
    load_state
    local container_pid
    container_pid="$(podman inspect --format '{{.State.Pid}}' "$SESSION_NAME")"
    # --user --net together, not --net alone: rootless podman's container
    # netns requires CAP_SYS_ADMIN inside the userns that owns it, which
    # the calling process only has once it also joins that userns. See
    # validate-egress.sh Step 4's own note for the real-hardware finding.
    nsenter --user --net --target "$container_pid" -- "$@"
}

cmd_status() {
    load_state
    if running; then
        local container_pid
        container_pid="$(podman inspect --format '{{.State.Pid}}' "$SESSION_NAME" 2>/dev/null || echo '?')"
        info "Up: name=$SESSION_NAME pid=$container_pid ssh_port=$GUEST_SSH_PORT"
        if [[ -n "${HARNESS_PID:-}" ]] && kill -0 "$HARNESS_PID" 2>/dev/null; then
            info "Harness running: pid=$HARNESS_PID log=$HARNESS_LOG"
        else
            info "Harness: not running"
        fi
    else
        info "No session up."
    fi
}

cmd_stop() {
    load_state
    if [[ -n "${SESSION_NAME:-}" ]]; then
        info "Removing $SESSION_NAME..."
        podman rm --force --ignore "$SESSION_NAME" > "$LOG_DIR/teardown.log" 2>&1 || true
    fi
    if [[ -n "${HARNESS_PID:-}" ]] && kill -0 "$HARNESS_PID" 2>/dev/null; then
        kill "$HARNESS_PID" 2>/dev/null || true
        wait "$HARNESS_PID" 2>/dev/null || true
    fi
    rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub" "$STATE_FILE"
    info "Stopped."
}

case "${1:-}" in
    start)  shift; cmd_start "$@" ;;
    exec)   shift; cmd_exec "$@" ;;
    ssh)    shift; cmd_ssh "$@" ;;
    netns)  shift; cmd_netns "$@" ;;
    status) cmd_status ;;
    stop)   cmd_stop ;;
    *)
        fail "Usage: $0 {start [--no-harness]|exec <cmd>|ssh|netns <cmd>|status|stop}"
        exit 1
        ;;
esac
