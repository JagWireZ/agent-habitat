//! `habitat-policy` -- schema types and loader for the shared config/policy
//! location.
//!
//! This crate is the single place the secrets blocklist, egress allowlist,
//! resource-limit defaults, and the git-history toggle are defined and
//! read from -- both `habitat-workspace` (blocklist, git-history toggle)
//! and `habitat-egress` (allowlist) depend on it rather than keeping their
//! own copies (`file-structure.md` Section 2).
//!
//! It reads:
//! - the default policy data under `/policy` at the repo root (Phase 2 for
//!   the blocklist, Phase 5 for the allowlist), and
//! - the checked-in operator config file (`habitat run --config ...`,
//!   assembled in Phase 7), which may only *add to* allowlist/blocklist
//!   entries or adjust resource limits/toggles -- never disable
//!   containment, blocklist enforcement, or patch validation (AGENTS.md
//!   Section 2; `docs/plan.md` Section 2.5's "one hardened setup" rule).
//!
//! No logic yet -- Phase 0 scaffolding only.
