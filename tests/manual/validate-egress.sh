#!/usr/bin/env bash
# tests/manual/validate-egress.sh
#
# Phase 5's real-hardware exit gate (tmp/wip/implementation-plan.md): a
# connection trace from inside a running guest must confirm an
# allowlisted destination succeeds, a non-allowlisted destination is
# blocked, and an allowlisted-lookalike or direct-IP bypass attempt is
# still blocked; and that the guest cannot construct a network path that
# skips the proxy, including via DNS. Neither this dev container nor
# this project's CI (ubuntu-latest, no nested virtualization) has real
# KVM, so this is a manual, host-dependent runbook, not a `cargo test`
# target -- see tests/manual/README.md. Re-run after any allowlist
# ruleset change, same as this exit gate requires.
#
# This script drives the proxy, DNS forwarder, and network/firewall setup
# directly (the same logic habitat-egress builds -- see
# crates/egress/src/{proxy,dns,network_setup}.rs), since Phase 7 hasn't
# wired `habitat run`'s full lifecycle yet. Update it if those modules
# change what they build, so this script keeps testing the actual
# configuration in use, not a stale copy of it.
#
# Also confirms/corrects network_setup.rs's real-hardware caveats. One
# already went through a wrong-then-reverted cycle here: `pasta --help`
# describes `-T`/`-U` as "TCP/UDP port forwarding to init namespace", which
# reads like "let the guest reach the host's loopback" but is actually the
# *other* direction -- auto-publishing whatever port the guest itself is
# listening on, the same thing `-t`/`-u` (which Podman already drives from
# `--publish`) cover explicitly. Forcing `--network pasta:-T,all,-U,all`
# made pasta auto-forward the guest's own sshd on top of Podman's already-
# explicit forward for the same port, and broke the SSH exec channel
# outright (confirmed on real hardware, then reverted -- see
# `network_setup::NETWORK_MODE`'s doc comment for the full trail). Whether
# a guest under plain `--network pasta` can reach a service bound on the
# host's own loopback at all -- which this crate's `--dns` pinning and
# proxy reachability both assume -- is accordingly **still an open
# question**, not a solved one; Step 3b below is where that gets checked
# for real, not assumed from either direction. The nftables ruleset built
# by `build_egress_firewall_rules` is similarly this crate's best current
# understanding of how to restrict a rootless `pasta` interface, not yet
# confirmed -- same "confirmed wrong on real hardware, then fixed" pattern
# as Phase 3's WORKSPACE_DISK_ANNOTATION and Phase 1's crun-krun
# package/binary name split.
#
# **Guest exec channel is SSH, reached by published port, not
# `podman exec` or a distinct guest IP** (docs/decisions/
# 0008-guest-exec-channel.md): `podman exec` does not work against the
# `krun` runtime at all, and `pasta` gives no separate, `podman
# inspect`-visible guest IP either -- this script's connection trace runs
# each check over SSH into the guest's published port, exactly as
# `validate-vm-launch.sh` and `validate-sync.sh` do.
#
# Requires: an AlmaLinux/Fedora host (dnf-family) with Podman + crun-krun
# + passt installed and /dev/kvm exposed -- i.e. a host that already
# passes tests/manual/validate-real-hardware.sh and
# tests/manual/validate-vm-launch.sh.
#
# Usage:
#   tests/manual/validate-egress.sh              # run the full pass
#   tests/manual/validate-egress.sh --report-only # print a prior run's summary

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$REPO_ROOT/tmp/wip/egress-validation"
SESSION_NAME="habitat-manual-egress-$$"
GUEST_IMAGE="${HABITAT_GUEST_IMAGE:-localhost/habitat-guest:alpine}"
WORKSPACE_DISK="$LOG_DIR/session.img"
PROXY_ADDR="127.0.0.1:8443"
# Must be the same IP as PROXY_ADDR, on port 53: podman's `--dns` flag (and
# network_setup::build_network_flags, which this script's PODMAN_ARGS
# mirrors) carries no port, so the guest's resolver always queries port 53
# -- see network_setup::DNS_LISTEN_PORT's doc comment for the false-positive
# this caused when this constant was previously 127.0.0.1:5300 (every
# lookup, including the allowlisted one, silently had nowhere to resolve).
DNS_ADDR="127.0.0.1:53"
# Must match crates/egress/src/network_setup.rs's NETWORK_MODE constant --
# duplicated here rather than shelled out to Rust to read it, same
# "kept in sync by hand, update both if one changes" tradeoff this script
# already makes for build_egress_firewall_rules's shape in Step 4's own
# instructions. Do NOT "fix" this to pasta:-T,all,-U,all -- see
# NETWORK_MODE's own doc comment for why that was tried and reverted (it
# broke the SSH exec channel outright).
PASTA_NETWORK_MODE="pasta"
# Must match network_setup::HOST_LOOPBACK_ADDR -- confirmed on real
# hardware that pointing the guest's `--dns` straight at PROXY_ADDR's own
# IP (127.0.0.1) never works: that address means the guest's *own*
# loopback from inside its own network namespace, never the host's. This
# fixed link-local address, paired with `pasta:--map-host-loopback=` on
# `--network` below, is what `pasta` actually translates to the host's
# real loopback -- see HOST_LOOPBACK_ADDR's own doc comment for why it's
# a fixed address rather than whatever the host's real network gateway
# happens to be (`pasta`'s own default for this option, and the first,
# wrong thing this project relied on).
HOST_LOOPBACK_ADDR="169.254.1.1"
SSH_KEY_PATH="$LOG_DIR/session-key"
GUEST_SSH_HOST="127.0.0.1"
AUDIT_LOG="$LOG_DIR/audit.jsonl"
HARNESS_LOG="$LOG_DIR/egress-harness.log"
HARNESS_PID=""

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

# Belt-and-braces: if any step below exits early (a failed launch, a
# failed nft apply, Ctrl-C), the harness started in Step 2 must not be
# left running past this script -- it's a throwaway validation process,
# never a background service this project expects to persist.
cleanup_harness() {
    if [[ -n "$HARNESS_PID" ]] && kill -0 "$HARNESS_PID" 2>/dev/null; then
        kill "$HARNESS_PID" 2>/dev/null || true
        wait "$HARNESS_PID" 2>/dev/null || true
    fi
}
trap cleanup_harness EXIT

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

record "# Egress validation run -- $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
record ""
record "Host: $(uname -a)"
record ""

# --- Step 1: host suitability -------------------------------------------
say "Step 1: host suitability"
if [[ ! -e /dev/kvm ]]; then
    fail "This host has no /dev/kvm -- run tests/manual/validate-real-hardware.sh first."
    record "- **ABORTED**: no /dev/kvm on this host."
    status "Step 1: host suitability" FAIL "no /dev/kvm on this host"
    exit 1
fi
for bin in podman krun passt nft ssh ssh-keygen; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        fail "$bin not found on PATH."
        record "- **ABORTED**: $bin not installed."
        status "Step 1: host suitability" FAIL "$bin not installed"
        exit 1
    fi
done
record "- /dev/kvm: present"
record "- podman: $(podman --version)"
record "- passt: $(passt --version 2>&1 | head -1 || echo 'present (no --version output)')"
record "- nft: $(nft --version)"

if ! podman image exists "$GUEST_IMAGE"; then
    if [[ "$GUEST_IMAGE" == "localhost/habitat-guest:alpine" ]]; then
        record "- $GUEST_IMAGE not found locally -- building it via guest/build.sh"
        "$REPO_ROOT/guest/build.sh"
    else
        fail "$GUEST_IMAGE (from \$HABITAT_GUEST_IMAGE) not found locally, and it isn't the default this script knows how to build. Build or pull it yourself first."
        record "- **ABORTED**: $GUEST_IMAGE not present and not buildable by this script."
        status "Step 1: host suitability" FAIL "$GUEST_IMAGE not present and not buildable"
        exit 1
    fi
fi
record "- guest image present: $GUEST_IMAGE"
status "Step 1: host suitability" PASS

# --- Step 2: start the local proxy and DNS forwarder on the host --------
say "Step 2: start the local egress proxy and DNS forwarder"
record "Building and launching \`crates/egress/examples/egress_harness.rs\` -- the real"
record "\`crate::proxy::run\`/\`crate::dns::run\` functions this project ships, not a stand-in"
record "(Phase 7 wires this into \`habitat run\`'s own lifecycle; until then this harness is"
record "the exact invocation, kept in-tree so it can't drift from those functions' real"
record "signatures):"
record ""

HARNESS_ARGS=(
    --proxy-addr "$PROXY_ADDR"
    --dns-addr "$DNS_ADDR"
    --audit-log "$AUDIT_LOG"
)
if [[ -n "${HABITAT_PROJECT_CONFIG:-}" ]]; then
    HARNESS_ARGS+=(--project-config "$HABITAT_PROJECT_CONFIG")
fi

# Built explicitly (rather than via `cargo run`) and launched by its own
# binary path -- port 53 is privileged, and the fix below grants
# CAP_NET_BIND_SERVICE on that exact binary file. `cargo run` re-execs
# through cargo itself, which is a needless extra hop for a capability
# that's only meaningful on the file actually calling bind(2).
cargo build --quiet -p habitat-egress --example egress_harness
HARNESS_BIN="$REPO_ROOT/target/debug/examples/egress_harness"
record "\$ $HARNESS_BIN ${HARNESS_ARGS[*]}"

launch_harness() {
    : > "$HARNESS_LOG"
    "$HARNESS_BIN" "${HARNESS_ARGS[@]}" >> "$HARNESS_LOG" 2>&1 &
    HARNESS_PID=$!

    HARNESS_READY=""
    for _ in $(seq 1 60); do
        if ! kill -0 "$HARNESS_PID" 2>/dev/null; then
            break
        fi
        if grep -q '^READY' "$HARNESS_LOG" 2>/dev/null; then
            HARNESS_READY=1
            break
        fi
        sleep 0.5
    done
}

launch_harness

if [[ -z "$HARNESS_READY" ]] && grep -qi 'bind: permission denied' "$HARNESS_LOG" 2>/dev/null; then
    fail "Binding on port 53 needs CAP_NET_BIND_SERVICE, which this run doesn't have."
    if [[ -t 0 ]] && command -v setcap >/dev/null 2>&1; then
        read -r -p "Grant it to $HARNESS_BIN via 'sudo setcap cap_net_bind_service=+ep' now? [y/N] " REPLY
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            if sudo setcap cap_net_bind_service=+ep "$HARNESS_BIN"; then
                record "- Granted \`cap_net_bind_service\` on $HARNESS_BIN via \`sudo setcap\` (one-time,"
                record "  scoped to this binary file; re-run \`cargo build\` clears it)."
                launch_harness
            else
                fail "setcap failed -- see above."
            fi
        fi
    fi
fi

if [[ -z "$HARNESS_READY" ]]; then
    fail "egress_harness did not report READY -- see $HARNESS_LOG"
    cat "$HARNESS_LOG" >&2
    record "- **ABORTED**: proxy/DNS forwarder harness failed to start (log: $HARNESS_LOG)."
    if grep -qi 'permission denied' "$HARNESS_LOG" 2>/dev/null; then
        record "  \`dns bind\` on port 53 needs a privilege this run doesn't have -- either"
        record "  grant \`cap_net_bind_service\` on \`$HARNESS_BIN\` yourself"
        record "  (\`sudo setcap cap_net_bind_service=+ep $HARNESS_BIN\`), or lower"
        record "  \`net.ipv4.ip_unprivileged_port_start\` on this host, then re-run."
    fi
    status "Step 2: start proxy/DNS harness" FAIL "did not report READY -- see $HARNESS_LOG"
    exit 1
fi
record "\`$(grep '^READY' "$HARNESS_LOG")\`"
record ""
record "- [x] Proxy started, listening on $PROXY_ADDR"
record "- [x] DNS forwarder started, listening on $DNS_ADDR"
status "Step 2: start proxy/DNS harness" PASS

# --- Step 3: build a session disk and launch with the pasta network ------
say "Step 3: build a disposable session disk and launch"
dd if=/dev/zero of="$WORKSPACE_DISK" bs=1M count=64 status=none
mkfs.ext4 -q -F "$WORKSPACE_DISK"
record "- Built a 64MB throwaway workspace disk at $WORKSPACE_DISK"

rm -f "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_PATH" -C habitat-session -q
AUTHORIZED_KEY="$(cat "$SSH_KEY_PATH.pub")"
record "- Generated a fresh session SSH keypair at $SSH_KEY_PATH (guest exec channel,"
record "  docs/decisions/0008-guest-exec-channel.md)"

PODMAN_ARGS=(
    run --detach --rm --name "$SESSION_NAME"
    --runtime krun
    --network "${PASTA_NETWORK_MODE}:--map-host-loopback=${HOST_LOOPBACK_ADDR}"
    --dns "$HOST_LOOPBACK_ADDR"
    # Without this, crun-krun silently falls back to libkrun's own
    # default TSI networking regardless of `--network pasta` above --
    # confirmed on real hardware (tmp/wip/egress-validation): a session
    # launched without this annotation booted with `tsi_hijack` on its
    # kernel command line and no virtio-net device at all, which is why
    # the DNS forwarder was unreachable in earlier runs -- there was no
    # real network for it to be reachable *on*. Per crun's own
    # krun.1.md: `krun.use_passt=NUM`, "When set to a value greater than
    # 0, enable passt-based networking in the microVM."
    --annotation "krun.use_passt=1"
    --cpus 2 --memory 2048m
    --annotation "io.habitat.vm.workspace-disk=${WORKSPACE_DISK}"
    --env "HABITAT_AUTHORIZED_KEY=${AUTHORIZED_KEY}"
    --publish "${GUEST_SSH_HOST}::22/tcp"
    "$GUEST_IMAGE"
)

set +e
podman "${PODMAN_ARGS[@]}" > "$LOG_DIR/launch.log" 2>&1
LAUNCH_EXIT=$?
set -e
cat "$LOG_DIR/launch.log"
record "- Launch exit: $LAUNCH_EXIT (log: $LOG_DIR/launch.log)"
if [[ "$LAUNCH_EXIT" -ne 0 ]]; then
    record "- **FAILED**: session did not launch with \`--network $PASTA_NETWORK_MODE\` -- if the"
    record "  log shows pasta/crun-krun rejected the flag, network_setup.rs's NETWORK_MODE"
    record "  constant needs correcting, then re-run this script."
    status "Step 3: build disk and launch" FAIL "exit=$LAUNCH_EXIT -- see $LOG_DIR/launch.log"
    rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
    exit 1
fi
record "- CONFIRMED: session launched with a pasta-backed network."
status "Step 3: build disk and launch" PASS

PORT_OUTPUT="$(podman port "$SESSION_NAME" 22/tcp 2>&1 || true)"
GUEST_SSH_PORT="${PORT_OUTPUT##*:}"
record "- \`podman port $SESSION_NAME 22/tcp\` -> \`$PORT_OUTPUT\` (port: $GUEST_SSH_PORT)"

SSH_OPTS=(-i "$SSH_KEY_PATH" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o BatchMode=yes -p "$GUEST_SSH_PORT")

run_trace() {
    # Each command below already carries its own in-guest timeout (curl's
    # `-m 5` or an explicit `timeout 5` prefix), but that only bounds
    # curl/nslookup itself -- it does nothing if the guest's TCP connect()
    # to an unreachable-but-not-yet-firewalled address (e.g. the direct-IP
    # bypass target, before Step 4's ruleset is applied) blocks in a way
    # that outlasts it, or if the SSH session itself stalls. Wrap the
    # whole thing in a host-side `timeout` too, generous enough not to cut
    # off a real 5s in-guest timeout's own output, so no single check can
    # ever hang this script indefinitely.
    timeout 15 ssh "${SSH_OPTS[@]}" "habitat@$GUEST_SSH_HOST" "$1" 2>&1 || echo BLOCKED
}

for _ in $(seq 1 30); do
    if ssh "${SSH_OPTS[@]}" "habitat@$GUEST_SSH_HOST" true 2>/dev/null; then
        break
    fi
    sleep 1
done

# --- Step 3b: DNS-pinning diagnostics -------------------------------------
# Isolates *why* a lookup fails before Step 5's trace runs: is the guest's
# resolver actually pointed at the proxy's DNS forwarder at all (resolv.conf),
# and if so, can it actually reach it (an explicit query naming
# $HOST_LOOPBACK_ADDR, bypassing resolv.conf entirely)? Both must hold for
# the default-resolver lookups in Step 5 to mean anything.
#
# Confirmed on real hardware (tmp/wip/egress-validation): the guest CAN
# reach a service on the host's own loopback under `pasta`, but not by
# querying the proxy's own IP (127.0.0.1) directly -- that address always
# means the guest's *own* loopback from inside its own network namespace.
# The actual mechanism is `pasta`'s `--map-host-loopback` translation:
# guest traffic sent to HOST_LOOPBACK_ADDR gets translated to the host's
# real loopback before delivery. This is no longer an open question.
say "Step 3b: DNS-pinning diagnostics"
RESOLV_CONF="$(run_trace "cat /etc/resolv.conf")"
record "- Guest \`/etc/resolv.conf\`:"
record '```'
record "$RESOLV_CONF"
record '```'
EXPLICIT_DNS_RESULT="$(run_trace "timeout 5 nslookup pypi.org $HOST_LOOPBACK_ADDR")"
record "- \`nslookup pypi.org $HOST_LOOPBACK_ADDR\` (explicit, bypassing resolv.conf -- proves whether the"
record "  forwarder is reachable at all, independent of whether resolv.conf itself is"
record "  correctly pinned):"
record '```'
record "$EXPLICIT_DNS_RESULT"
record '```'
DNS_OK=1
if echo "$EXPLICIT_DNS_RESULT" | grep -qi 'BLOCKED\|refused\|timed out\|no servers'; then
    DNS_OK=""
    record "  -- forwarder is NOT reachable from the guest at ${HOST_LOOPBACK_ADDR}:53. Confirm"
    record "  \`pasta\` actually got the \`--map-host-loopback=${HOST_LOOPBACK_ADDR}\` option (check"
    record "  the real \`pasta\` process argv on the host, e.g. \`ps aux | grep pasta\`) and that"
    record "  \`crun-krun\`/\`libkrun\` are new enough for \`krun.use_passt\` (crun >= 1.27.1 --"
    record "  see network_setup::KRUN_USE_PASST_ANNOTATION's doc comment)."
elif ! echo "$RESOLV_CONF" | grep -q "^nameserver ${HOST_LOOPBACK_ADDR}\$"; then
    DNS_OK=""
    record "  -- forwarder IS reachable, but resolv.conf isn't actually pointed at it -- \`--dns\`"
    record "  either didn't apply under \`--network $PASTA_NETWORK_MODE\`, or something in the"
    record "  guest (entrypoint.sh, a DHCP client) overwrote it after boot."
fi
if [[ -n "$DNS_OK" ]]; then
    record "  -- forwarder reachable and resolv.conf correctly pinned; Step 5's default-resolver"
    record "  lookups should work."
    status "Step 3b: DNS-pinning diagnostics" PASS
else
    status "Step 3b: DNS-pinning diagnostics" FAIL "see diagnostics above"
fi

# --- Step 4: apply the reachability-restricting firewall ruleset --------
say "Step 4: restrict the guest's pasta interface to the proxy only"
record "MANUAL: identify the pasta-created interface for this session (e.g. via"
record "\`ip link\` or podman's own network inspection output), generate the ruleset"
record "via \`habitat_egress::network_setup::build_egress_firewall_rules(iface, proxy_addr)\`,"
record "and apply it with \`nft -f <generated-ruleset>\`. Record the interface name and"
record "whether \`nft -f\` succeeded without root (rootless nftables in this user's own"
record "netns) or required a privilege this project's containment model does not allow:"
record ""
record "- [ ] pasta interface identified: ______________________"
record "- [ ] \`nft -f\` applied successfully, no elevated privilege required"
record ""
record "**Until this step is actually applied, expect every check in Step 5 to reach its"
record "real destination, allowlisted or not**: nothing before this point makes the proxy"
record "reachable from the guest's own outbound connections, and this ruleset's accept rule"
record "(destination = the proxy's own address) only helps once the guest's traffic is"
record "actually forced through it. Cross-check this against network_setup.rs's own"
record "\`build_egress_firewall_rules\` -- as written it default-denies everything except"
record "connections the guest itself dials *to* \`$PROXY_ADDR\`, but nothing in this repo yet"
record "redirects a guest's ordinary outbound :443 connections there (no DNAT rule, no"
record "in-guest proxy configuration) -- if that's still true when you read this, a"
record "genuinely allowed destination will fail closed once Step 4 is applied, which is a"
record "real gap in network_setup.rs to fix, not a mistake in this script."
status "Step 4: apply restricting firewall ruleset" MANUAL "not automated -- see printed instructions"

# --- Step 5: connection trace (the actual exit gate) ---------------------
say "Step 5: connection trace from inside the guest"
record ""
record "Running each of these over SSH against the guest and recording the actual result --"
record "not checking a box from inspection of the ruleset alone (docs/decisions/"
record "0008-guest-exec-channel.md -- podman exec does not work against krun at all):"
record '```'

record "\$ curl -sS -o /dev/null -w '%{http_code}\\n' https://pypi.org/   # allowlisted -- must succeed"
ALLOWED_RESULT="$(run_trace "curl -sS -o /dev/null -w '%{http_code}\\n' https://pypi.org/")"
record "$ALLOWED_RESULT"
record ""
record "\$ curl -sS -m 5 https://example.com/   # non-allowlisted -- must be blocked"
DENIED_RESULT="$(run_trace "curl -sS -m 5 https://example.com/")"
record "$DENIED_RESULT"
record ""
record "\$ curl -sS -m 5 https://githubusercontent.com.attacker.example/   # lookalike -- must be blocked"
LOOKALIKE_RESULT="$(run_trace "curl -sS -m 5 https://githubusercontent.com.attacker.example/")"
record "$LOOKALIKE_RESULT"
record ""
record "\$ curl -sS -m 5 --resolve pypi.org:443:1.2.3.4 https://pypi.org/   # direct-IP bypass -- must be blocked"
IP_BYPASS_RESULT="$(run_trace "curl -sS -m 5 --resolve pypi.org:443:1.2.3.4 https://pypi.org/")"
record "$IP_BYPASS_RESULT"
record ""
record "\$ nslookup pypi.org 8.8.8.8   # DNS bypass, resolver other than the pinned proxy path -- must be blocked"
DNS_BYPASS_RESULT="$(run_trace "timeout 5 nslookup pypi.org 8.8.8.8")"
record "$DNS_BYPASS_RESULT"
record '```'
record ""
record "MANUAL: confirm each result above actually shows what its label says (a real HTTP"
record "200/301-class status for the allowed case; BLOCKED, a connection error, or a timeout"
record "for every denied case) -- these are captured automatically but still need a human"
record "read, since a curl/nslookup error message's exact shape varies."
record ""
record "- [ ] Allowlisted destination succeeded (recorded HTTP status above)"
record "- [ ] Non-allowlisted destination was blocked"
record "- [ ] Allowlist-lookalike hostname was blocked"
record "- [ ] Direct-IP bypass was blocked"
record "- [ ] Direct-to-8.8.8.8 DNS bypass was blocked (confirms DNS pinning actually holds,"
record "      not just that the SNI proxy would have denied whatever it resolved to)"
status "Step 5: allowlisted destination succeeds" MANUAL "recorded: $ALLOWED_RESULT"
status "Step 5: non-allowlisted destination blocked" MANUAL "recorded: $DENIED_RESULT"
status "Step 5: allowlist-lookalike blocked" MANUAL "recorded: $LOOKALIKE_RESULT"
status "Step 5: direct-IP bypass blocked" MANUAL "recorded: $IP_BYPASS_RESULT"
status "Step 5: DNS bypass (8.8.8.8) blocked" MANUAL "recorded: $DNS_BYPASS_RESULT"

# --- Step 6: teardown ------------------------------------------------------
say "Step 6: teardown"
set +e
podman rm --force --ignore "$SESSION_NAME" > "$LOG_DIR/teardown.log" 2>&1
TEARDOWN_EXIT=$?
set -e
rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
record "- Teardown exit: $TEARDOWN_EXIT (log: $LOG_DIR/teardown.log)"

cleanup_harness
HARNESS_PID=""
record "- [x] Proxy and DNS forwarder stopped (harness log: $HARNESS_LOG, audit log: $AUDIT_LOG)"
record ""
record "MANUAL: if Step 4 was actually applied (this script does not apply it itself --"
record "see that step's own note), also remove its nftables table:"
record "\`nft delete table inet habitat_egress\`."
record ""
record "- [ ] nftables ruleset removed (only applicable if Step 4 was applied)"
status "Step 6: teardown" PASS
status "Step 6: nftables ruleset removed" MANUAL "only applicable if Step 4 was applied"

result_summary

say "Done"
echo "Summary written to $SUMMARY -- fold the connection-trace results from Step 5 into it by hand."
