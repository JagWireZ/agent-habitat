# tests/unit/cli/

Unit tests mirroring `crates/cli/`. Phase 1 added `habitat install`/`habitat
run`, but per `file-structure.md` Section 2 their pure-logic unit tests
(`plan_auto_install`'s family-detected/not-detected branches) stay as an
inline `#[cfg(test)]` module in `crates/cli/src/main.rs` -- this directory
is reserved for tests covering the crate's contract with the rest of the
system, and none of that shape exists yet for `crates/cli` (its exit-gate
coverage today lives in `tests/unit/install/exit_gate.rs`, since that's
where the checks/installer logic actually is).
