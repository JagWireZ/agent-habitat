# tests/manual/

Host-dependent runbooks that a human runs deliberately against real
hardware -- not `cargo test` targets, and not something CI can run, since
they need a specific class of real machine (e.g. dnf-family with hardware
virtualization exposed) plus `sudo` and, for their negative cases,
someone's explicit decision to temporarily break something on that
machine.

**Prerequisite for `validate-vm-launch.sh`, `validate-sync.sh`, and
`validate-egress.sh`:** the guest image (`guest/Containerfile`) must
already be built and tagged as `localhost/habitat-guest:alpine` --
`guest/build.sh` does that, and each of these three scripts now runs it
automatically the first time if the image isn't found locally. Without
it, `podman run` fails trying to pull a nonexistent `localhost` image
from a registry rather than finding a launch-flag problem; see
`guest/README.md`.

This sits alongside `tests/unit/<domain>/`, `tests/integration/`, and
`tests/adversarial/` (see `file-structure.md`) rather than inside any of
them: those three are all automated, in-process test suites that mirror
or cut across the crate tree; what lives here is scripted-but-manual
validation that exists specifically because some part of the system can't
be verified any other way (e.g. `/dev/kvm` behavior, a real package
manager, a real `sudo` prompt).

- `validate-real-hardware.sh` -- Phase 1's remaining real-hardware exit
  gate (`tmp/wip/phase-1-tasks.md` §10): confirms `habitat install`/
  `habitat run` behave correctly on a real dnf-family host (AlmaLinux/
  Fedora) with virtualization enabled. Reused, not duplicated, at Phase
  8's validation run-book.

- `validate-vm-launch.sh` -- Phase 3's real-hardware exit gate: launches
  a real session through Podman + `krun` against a throwaway staging
  directory, then runs the three required escape attempts (host files,
  host processes, host network namespace) itself, against the still-live
  session, capturing real output on both sides -- not printed as
  instructions for a human to copy into a second terminal (an earlier
  version did that, and teardown ran before anyone had a window to act
  on it). Also checks, from inside the guest, that `/workspace` is
  actually populated and writable as the `habitat` user -- the exact gap
  that let the original `virtio-blk` attachment mechanism ship broken
  unnoticed (see `docs/decisions/0005-storage-layer.md`'s Correction).
  Only the network-route comparison still needs a human's judgment.
  Confirms teardown leaves no residual container or staging directory,
  and doubles as the confirmation (or correction) point for
  `launcher.rs`'s bind-mount flag's real-hardware caveats. Reused, not
  duplicated, at Phase 8's validation run-book.

- `validate-sync.sh` -- Phase 4's real-hardware exit gate: the one part
  of the two-point sync mechanism (`habitat_workspace::sync`) that needs
  a real, booted guest -- a live-session process inventory confirming no
  continuous/background sync daemon exists beyond the two discrete
  invocations (`sync_host_to_sandbox`/`sync_sandbox_to_host`). Everything
  else in that phase's exit gate (malformed-patch handling, the
  blocklist re-check, the no-op short-circuit, sync perf against real
  fixtures) is covered by `tests/unit/workspace/sync_exit_gate.rs` and
  `tests/adversarial/sync_patch_validation.rs` instead. Reused, not
  duplicated, at Phase 8's validation run-book.

- `validate-egress.sh` -- Phase 5's real-hardware exit gate: a
  connection trace from inside a running guest, launched with the real
  `pasta`-backed network and the nftables reachability restriction
  `habitat_egress::network_setup` builds, confirming an allowlisted
  destination succeeds, a non-allowlisted destination and an
  allowlist-lookalike hostname are both blocked, and neither a
  direct-IP nor a direct-DNS-server bypass can route around the proxy.
  Also the confirmation (or correction) point for `network_setup.rs`'s
  `--network pasta` and nftables-ruleset real-hardware caveats, same
  "confirmed wrong on real hardware, then fixed" pattern as
  `validate-vm-launch.sh`'s bind-mount-vs-`virtio-blk` caveat
  (`docs/decisions/0005-storage-layer.md`'s Correction).
  Everything in this phase's exit gate that doesn't need a booted guest
  (the SNI-based allow/deny decision itself, the relay, the DNS
  forwarder, the argv/ruleset construction) is exercised for real over
  loopback sockets in `tests/unit/egress/exit_gate.rs` and
  `tests/adversarial/egress_bypass.rs` instead. Reused, not duplicated,
  at Phase 8's validation run-book -- and, per this phase's own exit
  gate, re-run after any allowlist ruleset change.

- `validate-habitat-run.sh` -- Phase 7's real-hardware exit gate: an
  end-to-end `habitat run --config sandbox.yaml -- <agent>` session
  across multiple prompts, with a real host-side edit made between
  prompts and a real agent tool call (a tiny fake one-shot agent
  fixture), confirming the expected audit event sequence and that the
  agent's own change is really synced back into the project directory --
  not just reported. Unlike the three scripts above, this one drives the
  real `habitat` binary directly instead of hand-rolling the
  `podman`/`ssh` commands it builds, since that binary (Phase 7's own
  deliverable) now exists. Also the confirmation point for
  `habitat_cli::run::apply_egress_firewall_in_container`'s `nsenter`-based
  firewall wiring, ported from this script's own `PASTA_IFACE` discovery
  but not yet exercised by that exact function on real hardware. Not yet
  run against real hardware in this session -- do not treat Phase 7 as
  fully real-hardware-validated until this runbook's checkboxes are
  filled in from an actual run.
