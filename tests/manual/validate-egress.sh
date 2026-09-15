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
# Also confirms/corrects network_setup.rs's real-hardware caveats: the
# `--network pasta` flag's actual behavior under crun-krun (rather than
# plain crun), and whether the nftables ruleset built by
# `build_egress_firewall_rules` is the right mechanism for restricting a
# rootless pasta interface, are this crate's best current understanding,
# not yet confirmed against real hardware -- same "confirmed wrong on
# real hardware, then fixed" pattern as Phase 3's WORKSPACE_DISK_ANNOTATION
# and Phase 1's crun-krun package/binary name split. If any step below
# shows the flag or ruleset isn't doing what's documented, fix
# network_setup.rs and re-run.
#
# **Guest exec channel is SSH, not `podman exec`**
# (docs/decisions/0008-guest-exec-channel.md): `podman exec` does not
# work against the `krun` runtime at all -- this script's connection
# trace (Step 5) runs each check over SSH into the guest, exactly as
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
DNS_ADDR="127.0.0.1:5300"
SSH_KEY_PATH="$LOG_DIR/session-key"

mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.md"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
fail() { printf '\033[31m%s\033[0m\n' "$1" >&2; }

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

record "# Egress validation run -- $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
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
for bin in podman krun passt nft ssh ssh-keygen; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        fail "$bin not found on PATH."
        record "- **ABORTED**: $bin not installed."
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
        exit 1
    fi
fi
record "- guest image present: $GUEST_IMAGE"

# --- Step 2: start the local proxy and DNS forwarder on the host --------
say "Step 2: start the local egress proxy and DNS forwarder"
record "MANUAL: start \`habitat-egress\`'s proxy (crates/egress::proxy::run) bound to $PROXY_ADDR"
record "with the effective allowlist for this project, and its DNS forwarder"
record "(crates/egress::dns::run) bound to $DNS_ADDR. There is no standalone binary yet"
record "(Phase 7 wires \`habitat run\`'s lifecycle) -- run them via a throwaway"
record "\`cargo run --example\` or a debug harness pointed at those functions, and"
record "record the exact invocation used here:"
record ""
record "- [ ] Proxy started, listening on $PROXY_ADDR"
record "- [ ] DNS forwarder started, listening on $DNS_ADDR"

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
    --network pasta
    --dns "${PROXY_ADDR%%:*}"
    --cpus 2 --memory 2048m
    --annotation "io.habitat.vm.workspace-disk=${WORKSPACE_DISK}"
    --env "HABITAT_AUTHORIZED_KEY=${AUTHORIZED_KEY}"
    "$GUEST_IMAGE"
)

set +e
podman "${PODMAN_ARGS[@]}" > "$LOG_DIR/launch.log" 2>&1
LAUNCH_EXIT=$?
set -e
cat "$LOG_DIR/launch.log"
record "- Launch exit: $LAUNCH_EXIT (log: $LOG_DIR/launch.log)"
if [[ "$LAUNCH_EXIT" -ne 0 ]]; then
    record "- **FAILED**: session did not launch with \`--network pasta\` -- if the log shows"
    record "  pasta/crun-krun rejected the flag, network_setup.rs's NETWORK_MODE constant needs"
    record "  correcting, then re-run this script."
    rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
    exit 1
fi
record "- CONFIRMED: session launched with a pasta-backed network."

GUEST_ADDR="$(podman inspect --format '{{.NetworkSettings.IPAddress}}' "$SESSION_NAME" | tr -d '[:space:]')"
record "- Guest address: $GUEST_ADDR"
for _ in $(seq 1 30); do
    if ssh "${SSH_OPTS[@]}" "habitat@$GUEST_ADDR" true 2>/dev/null; then
        break
    fi
    sleep 1
done

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

# --- Step 5: connection trace (the actual exit gate) ---------------------
say "Step 5: connection trace from inside the guest"
record ""
record "Running each of these over SSH against the guest and recording the actual result --"
record "not checking a box from inspection of the ruleset alone (docs/decisions/"
record "0008-guest-exec-channel.md -- podman exec does not work against krun at all):"
record '```'

run_trace() {
    ssh "${SSH_OPTS[@]}" "habitat@$GUEST_ADDR" "$1" 2>&1 || echo BLOCKED
}

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

# --- Step 6: teardown ------------------------------------------------------
say "Step 6: teardown"
set +e
podman rm --force --ignore "$SESSION_NAME" > "$LOG_DIR/teardown.log" 2>&1
TEARDOWN_EXIT=$?
set -e
rm -f "$WORKSPACE_DISK" "$SSH_KEY_PATH" "$SSH_KEY_PATH.pub"
record "- Teardown exit: $TEARDOWN_EXIT (log: $LOG_DIR/teardown.log)"
record "MANUAL: also stop the proxy and DNS forwarder processes started in Step 2, and"
record "remove the nftables table applied in Step 4 (\`nft delete table inet habitat_egress\`)."
record ""
record "- [ ] Proxy and DNS forwarder stopped"
record "- [ ] nftables ruleset removed"

say "Done"
echo "Summary written to $SUMMARY -- fold the connection-trace results from Step 5 into it by hand."
