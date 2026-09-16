#!/usr/bin/env bash
# tests/manual/validate-real-hardware.sh
#
# Phase 1's real-hardware exit gate (see tmp/wip/phase-1-tasks.md §10 and
# tmp/wip/implementation-plan.md's Phase 1/Phase 8 sections) requires
# running `habitat` on an actual dnf-family host with hardware
# virtualization exposed -- not just against FakeEnvironment. This script
# automates the safe, non-destructive parts of that pass; it prints
# instructions rather than acting for the two steps that deliberately
# break something on your machine (see step 5 and step 6 below), since
# those need a human decision, not a script making it for them.
#
# This is a manual, host-dependent runbook, not a `cargo test` target --
# see tests/manual/README.md for why it lives here instead of
# tests/{unit,integration,adversarial}.
#
# Usage:
#   tests/manual/validate-real-hardware.sh              # run the full safe pass
#   tests/manual/validate-real-hardware.sh --report-only # print a prior run's summary
#
# Requires: this repo checked out with a Rust toolchain (cargo) on the
# host you're validating -- not run against a remote target.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/target/release/habitat"
LOG_DIR="$REPO_ROOT/tmp/wip/real-hardware-validation"
AUDIT_LOG="${XDG_STATE_HOME:-$HOME/.local/state}/habitat/audit.log"

mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.md"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
note() { printf '%s\n' "$1"; }
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

record "# Real-hardware validation run -- $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
record ""
record "Host: $(uname -a)"
if [[ -r /etc/os-release ]]; then
    record "Distro: $(. /etc/os-release; echo "$PRETTY_NAME")"
fi
record ""

# --- Step 1: confirm this is actually a suitable host -----------------
say "Step 1: host suitability"

FAMILY="unknown"
if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}${ID_LIKE:-}" in
        *fedora*|*rhel*|*almalinux*|*rocky*|*centos*) FAMILY="dnf" ;;
        *debian*|*ubuntu*) FAMILY="apt" ;;
    esac
fi
record "- Detected package-manager family: $FAMILY"
if [[ "$FAMILY" != "dnf" ]]; then
    fail "This host is not dnf-family ($FAMILY). Phase 1's apt-side real-hardware pass is already recorded (see tmp/wip/phase-1-tasks.md); this script's purpose is specifically the dnf side (AlmaLinux/Fedora). Re-run this on an AlmaLinux or Fedora host."
    record "- **ABORTED**: not a dnf-family host."
    status "Step 1: host suitability" FAIL "not dnf-family ($FAMILY)"
    exit 1
fi

if [[ -e /dev/kvm ]]; then
    record "- /dev/kvm: present"
    KVM_PRESENT=1
else
    record "- /dev/kvm: **absent** -- this host cannot validate the success-path checks below. It can still validate the KVM-absence detection itself (step 4 will confirm that instead of the success path)."
    KVM_PRESENT=0
fi

if grep -qE 'vmx|svm' /proc/cpuinfo; then
    record "- CPU virtualization flag: present ($(grep -oE 'vmx|svm' /proc/cpuinfo | head -1))"
else
    record "- CPU virtualization flag: **absent**"
fi
status "Step 1: host suitability" PASS "dnf-family, kvm=$KVM_PRESENT"

# --- Step 2: build ------------------------------------------------------
say "Step 2: build habitat"
set +e
( cd "$REPO_ROOT" && cargo build --release -p habitat-cli ) 2>&1 | tee "$LOG_DIR/build.log" | tail -5
BUILD_EXIT=${PIPESTATUS[0]}
set -e
record "- Build: see $LOG_DIR/build.log"
if [[ "$BUILD_EXIT" -eq 0 ]]; then
    status "Step 2: build habitat" PASS
else
    status "Step 2: build habitat" FAIL "cargo build exited $BUILD_EXIT"
    exit 1
fi

# --- Step 3: capture the starting (likely broken) state -----------------
say "Step 3: starting state (before any install)"
set +e
"$BIN" run -- true > "$LOG_DIR/01-run-before.log" 2>&1
RUN_BEFORE_EXIT=$?
set -e
record "- \`habitat run\` before install: exit=$RUN_BEFORE_EXIT (log: $LOG_DIR/01-run-before.log)"
status "Step 3: starting state" PASS "recorded exit=$RUN_BEFORE_EXIT"

# --- Step 4: KVM-absence detection, or note it's already covered --------
say "Step 4: KVM-absence detection"
if [[ "$KVM_PRESENT" -eq 0 ]]; then
    if grep -q "Hardware virtualization" "$LOG_DIR/01-run-before.log" && grep -qi "not available" "$LOG_DIR/01-run-before.log"; then
        record "- CONFIRMED: real KVM absence correctly reported (not a false positive)."
        status "Step 4: KVM-absence detection" PASS "absence correctly reported"
    else
        fail "KVM is absent but the checklist above didn't report it as failed -- investigate before going further."
        record "- **FAILED**: KVM absent but not reported as failed. See $LOG_DIR/01-run-before.log."
        status "Step 4: KVM-absence detection" FAIL "absence not reported -- see $LOG_DIR/01-run-before.log"
        exit 1
    fi
else
    record "- /dev/kvm is present on this host, so this step can't exercise the absence case here."
    record "  To still record it: revoke access deliberately (see below), re-run, then restore."
    record ""
    record "  MANUAL STEP (not automated -- this changes your access to a real device):"
    record '    sudo chmod 000 /dev/kvm   # or: remove yourself from the kvm group and log out/in'
    record "    $BIN run -- true          # confirm it now reports absence"
    record '    sudo chmod 666 /dev/kvm   # restore (default on Fedora/AlmaLinux -- confirm with '"'"'stat /dev/kvm'"'"' if unsure)'
    status "Step 4: KVM-absence detection" MANUAL "/dev/kvm present -- see printed instructions"
fi

# --- Step 5: real dnf auto-install (the actual gap this script closes) --
say "Step 5: real dnf auto-install"
note "This runs: echo y | $BIN install -v"
note "It will invoke real 'sudo dnf install -y podman' / 'sudo dnf install -y crun-krun' if either is missing."
set +e
echo y | "$BIN" install -v > "$LOG_DIR/02-install.log" 2>&1
INSTALL_EXIT=$?
set -e
cat "$LOG_DIR/02-install.log"
record "- \`habitat install\` (auto-confirmed): exit=$INSTALL_EXIT (log: $LOG_DIR/02-install.log)"
if [[ "$INSTALL_EXIT" -eq 0 ]]; then
    record "- CONFIRMED: real dnf install of podman + crun-krun succeeded end-to-end."
    status "Step 5: real dnf auto-install" PASS
else
    record "- Install did not fully succeed -- see log. If this host lacks /dev/kvm, that alone will keep this at non-zero even after packages install correctly; check the log for which specific check is still failing."
    status "Step 5: real dnf auto-install" FAIL "exit=$INSTALL_EXIT -- see $LOG_DIR/02-install.log"
fi

# --- Step 6: real success-path confirmation (only meaningful with KVM) --
say "Step 6: success-path confirmation"
if [[ "$KVM_PRESENT" -eq 1 ]]; then
    set +e
    "$BIN" run -- true > "$LOG_DIR/03-run-after.log" 2>&1
    RUN_AFTER_EXIT=$?
    set -e
    record "- \`habitat run\` after install: exit=$RUN_AFTER_EXIT (log: $LOG_DIR/03-run-after.log)"
    if grep -q "Everything looks good" "$LOG_DIR/03-run-after.log"; then
        record "- CONFIRMED: full success path (all four checks pass) reached on real hardware."
        status "Step 6: success-path confirmation" PASS
    else
        record "- NOT YET CONFIRMED: preflight still reports a failure after install -- see log."
        status "Step 6: success-path confirmation" FAIL "preflight still failing -- see $LOG_DIR/03-run-after.log"
    fi
else
    record "- Skipped: this host has no /dev/kvm, so the full success path can't be reached here regardless of package installs."
    status "Step 6: success-path confirmation" SKIP "no /dev/kvm on this host"
fi

# --- Step 7: broken-runtime negative case (manual, destructive) --------
say "Step 7: broken crun-krun (manual)"
record ""
record "MANUAL STEP (not automated -- this removes a package you likely just installed):"
record '```'
record "sudo dnf remove -y crun-krun"
record "$BIN run -- true   # confirm: fails closed, non-zero exit, preflight-failure/krun-runtime tagged"
record "sudo dnf install -y crun-krun   # restore"
record '```'
status "Step 7: broken-runtime negative case" MANUAL "not automated -- see printed instructions"

# --- Step 8: audit log ---------------------------------------------------
say "Step 8: audit log"
if [[ -f "$AUDIT_LOG" ]]; then
    cp "$AUDIT_LOG" "$LOG_DIR/audit.log.snapshot"
    record "- Audit log snapshot saved to $LOG_DIR/audit.log.snapshot"
    record "- Distinct tags seen: $(grep -o '"kind":"[a-z-]*"' "$AUDIT_LOG" | sort -u | tr '\n' ' ')"
    status "Step 8: audit log" PASS "snapshot saved"
else
    record "- No audit log found at $AUDIT_LOG"
    status "Step 8: audit log" SKIP "no audit log at $AUDIT_LOG"
fi

result_summary

say "Done"
note "Summary written to $SUMMARY -- fold the relevant lines into tmp/wip/phase-1-tasks.md's real-hardware checkbox."
note "Steps 4 and 7 above list manual commands for the two negative cases this script won't run unattended."
