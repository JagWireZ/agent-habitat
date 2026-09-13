//! `habitat-audit` -- the unified audit log for everything crossing the
//! host/sandbox boundary.
//!
//! A minimal sink is established in Phase 1 (for preflight failures); full
//! content is added in Phase 6: session start/stop, preflight pass/fail,
//! VM launch/teardown, every proxy allow/deny decision with destination,
//! every sync event including validation outcome.
//!
//! Explicit scope note (carried into operator-facing output too): this is
//! boundary-only audit, not in-sandbox activity logging -- see AGENTS.md
//! Section 4's deferred-items table.
//!
//! Log content is treated as untrusted, attacker-influenced input from day
//! one: no shell interpolation of any logged string anywhere it is parsed,
//! displayed, or piped (AGENTS.md Section 2, invariant 12).
//!
//! No logic yet -- Phase 0 scaffolding only.
