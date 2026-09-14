# tests/unit/install/

Unit tests mirroring `crates/install/`.

Phase 1 populated this with black-box exit-gate tests -- see
`exit_gate.rs`, wired into `cargo test` via the `[[test]]` target in
`crates/install/Cargo.toml`:

- `preflight_reports_missing_kvm_not_a_false_positive` -- the
  no-KVM-exposed exit-gate scenario.
- `broken_krun_runtime_install_fails_closed_with_distinct_tag` -- the
  broken-Podman/krun exit-gate scenario.
- `install_run_twice_on_already_correct_host_makes_no_changes` -- the
  installer-idempotency exit-gate scenario.

Pure internal-logic unit tests for individual checks (host-OS gate, KVM
probe, podman, krun-runtime) stay as inline
`#[cfg(test)]` modules in `crates/install/src/checks.rs` and
`crates/install/src/preflight.rs`, per `file-structure.md` Section 2 --
only tests covering the domain's contract with the rest of the system
(the exit-gate cases above) live here.
