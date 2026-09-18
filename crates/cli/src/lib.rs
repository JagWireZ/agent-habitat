//! Library half of the `habitat` CLI: everything `src/main.rs` calls into,
//! pulled out to a `lib` target so `tests/unit/cli/`,
//! `tests/adversarial/`, and `tests/integration/` can exercise it
//! directly (a binary crate's own modules aren't visible to external test
//! targets).

pub mod output;
pub mod run;
