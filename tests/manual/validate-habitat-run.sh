#!/usr/bin/env bash
# tests/manual/validate-habitat-run.sh
#
# Phase 7's real-hardware exit gate (tmp/wip/implementation-plan.md): an
# end-to-end `habitat run --config sandbox.yaml -- <agent>` run across
# multiple prompts, at least one host-side edit between prompts, and at
# least one agent tool call, must produce the expected sequence of audit
# events and applied patches in the real working directory. Re-running
# `habitat install` a second time on an already-correct host must make no
# unwanted changes (already covered by
# `tests/manual/validate-real-hardware.sh`'s own exit gate -- this script
# doesn't re-derive that, only confirms it still holds with `habitat run`
# now also present).
#
# Unlike `validate-vm-launch.sh`/`validate-sync.sh`/`validate-egress.sh`,
# which had to hand-roll the exact `podman`/`ssh` commands `habitat-vm`/
# `habitat-workspace` build (since no CLI driver existed yet), this
# script drives the real `habitat` binary directly -- Phase 7's whole
# point. If this script's expectations ever drift from what `habitat run`
# actually does, that is itself a real Phase 7 regression to fix, not a
# stale copy of internal logic to update.
#
# **Agent contract (docs/decisions/0009-run-driver-prompt-loop.md):** the
# command named after `--` must accept a single prompt as its final
# positional argument and exit once it has answered that prompt -- a
# one-shot invocation per prompt, not a persistent interactive REPL. This
# script uses a tiny fake "agent" (`tests/manual/fixtures/fake-agent.sh`,
# written by this script into the guest-reachable project so it travels
# through the disk build like any other project file) that, on its first
# invocation, also creates `from-agent.txt` -- standing in for a real
# agent's own file edit, so this run has something real to sync back.
#
# Requires: a host that already passes `validate-real-hardware.sh` and
# `validate-vm-launch.sh`/`validate-sync.sh`/`validate-egress.sh` (Podman
# + crun-krun + passt + nft + nsenter, /dev/kvm exposed, the guest image
# built).
#
# **Real-hardware caveat carried forward, not newly introduced here:**
# `habitat_cli::run::apply_egress_firewall_in_container`'s use of
# `nsenter`/`ip -o link show` to find the session's `pasta` interface
# from the host side is this project's best current understanding,
# ported from `validate-egress.sh`'s own hand-verified steps, but not yet
# exercised by that exact function against real hardware -- this is
# where that gets confirmed or corrected. Likewise the DNS forwarder's
# need for a privileged bind on port 53
# (`crates/cli/src/main.rs::EGRESS_PROXY_ADDR`'s own doc comment).
#
# Usage:
#   tests/manual/validate-habitat-run.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$REPO_ROOT/tmp/wip/habitat-run-validation"
PROJECT_DIR="$LOG_DIR/project"
CONFIG_PATH="$PROJECT_DIR/sandbox.yaml"
AGENT_PATH="$PROJECT_DIR/fake-agent.sh"
REPORT="$LOG_DIR/report.md"

mkdir -p "$LOG_DIR"
rm -rf "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR"

record() { echo "$1" | tee -a "$REPORT"; }
: > "$REPORT"
record "# habitat run -- real-hardware validation ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
record ""

# --- Step 0: prerequisites -------------------------------------------------
record "## Step 0: prerequisites"
MISSING=0
for bin in podman krun passt nft nsenter ssh ssh-keygen; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        record "- MISSING: \`$bin\` not on PATH"
        MISSING=1
    fi
done
if [ ! -e /dev/kvm ]; then
    record "- MISSING: /dev/kvm not present"
    MISSING=1
fi
if [ "$MISSING" -ne 0 ]; then
    record ""
    record "Prerequisites not met -- run \`validate-real-hardware.sh\` first."
    exit 1
fi
record "- All required binaries present, /dev/kvm exposed."
record ""

# --- Step 1: seed a tiny real project ---------------------------------------
record "## Step 1: seed a project"
echo "hello project" > "$PROJECT_DIR/README.md"
cat > "$CONFIG_PATH" <<'YAML'
resource_limits:
  cpus: 1
  memory_mb: 1024
secrets_scan:
  content: disabled
YAML
cat > "$AGENT_PATH" <<'SH'
#!/usr/bin/env sh
# Fake one-shot agent for validate-habitat-run.sh: on its first
# invocation, creates from-agent.txt; every invocation echoes the prompt
# it was given (its last argument) so the operator sees a response.
prompt="${*: -1}"
if [ ! -f from-agent.txt ]; then
    echo "hello from the agent" > from-agent.txt
fi
echo "fake-agent answered: $prompt"
SH
chmod +x "$AGENT_PATH"
record "- Project seeded at \`$PROJECT_DIR\` with \`sandbox.yaml\` (content scan off, tight resource limits) and a fake one-shot agent."
record ""

# --- Step 2: build the real habitat binary ----------------------------------
record "## Step 2: build \`habitat\`"
(cd "$REPO_ROOT" && cargo build --release -p habitat-cli 2>&1 | tail -5 | sed 's/^/    /' | tee -a "$REPORT" >/dev/null)
HABITAT_BIN="$REPO_ROOT/target/release/habitat"
record "- Built \`$HABITAT_BIN\`."
record ""

# --- Step 3: run habitat run across multiple prompts, with a host edit -----
record "## Step 3: \`habitat run\` across multiple prompts"
record "Prompt 1 sent immediately; a host-side edit is made before prompt 2;"
record "then the session is ended with \`exit\`."
(
    cd "$PROJECT_DIR"
    printf 'summarize this project\n'
    sleep 1
    echo "a note the operator added between prompts" > notes.txt
    printf 'add a test for the new behavior\n'
    printf 'exit\n'
) | (cd "$PROJECT_DIR" && "$HABITAT_BIN" run --config "$CONFIG_PATH" -- "$AGENT_PATH" 2>&1 | tee -a "$REPORT")
RUN_EXIT=$?
record ""
record "- \`habitat run\` exit code: $RUN_EXIT"
record ""

# --- Step 4: confirm applied patches in the real working directory --------
record "## Step 4: confirm real applied patches"
if [ -f "$PROJECT_DIR/from-agent.txt" ]; then
    record "- [ ] \`from-agent.txt\` present in the real project directory (synced back from the guest)."
else
    record "- MISSING: \`from-agent.txt\` was not synced back -- check the audit log and \`habitat run\` output above."
fi
record ""

# --- Step 5: audit log check ------------------------------------------------
record "## Step 5: audit log"
AUDIT_LOG="${XDG_STATE_HOME:-$HOME/.local/state}/habitat/audit.log"
if [ -f "$AUDIT_LOG" ]; then
    record "- Last 10 lines of \`$AUDIT_LOG\`:"
    tail -10 "$AUDIT_LOG" | sed 's/^/    /' | tee -a "$REPORT" >/dev/null
else
    record "- MISSING: no audit log found at \`$AUDIT_LOG\`."
fi
record ""

# --- Step 6: re-run install a second time (idempotency, still holds) -------
record "## Step 6: re-run \`habitat install\` a second time"
"$HABITAT_BIN" install 2>&1 | tail -5 | sed 's/^/    /' | tee -a "$REPORT" >/dev/null
record "- Confirm by eye above that the second run reports everything already installed/no changes made."
record ""

record "## Checklist (fill in by hand after reviewing this report)"
record "- [ ] Multiple prompts processed in one session."
record "- [ ] The host-side edit (\`notes.txt\`) reached the guest before the second prompt (check \`sync-applied\` in the audit log above, host->sandbox direction)."
record "- [ ] At least one agent tool call ran (the fake agent's own \"fake-agent answered: ...\" lines appear in Step 3's output)."
record "- [ ] The agent's own change (\`from-agent.txt\`) was synced back and is really present in \`$PROJECT_DIR\`."
record "- [ ] Every documented config key (\`resource_limits\`, \`secrets_scan\`, etc.) was exercised at least once across this project's validation history without ever bypassing an invariant (cross-reference \`tests/adversarial/config_cannot_weaken_invariants.rs\`, which covers this without real hardware)."
record "- [ ] Re-running \`habitat install\` a second time made no unwanted changes."
record ""
record "Report saved to $REPORT"
