//! `habitat-egress` -- the local proxy and default-deny allowlist.
//!
//! Phase 5 responsibility (see `tmp/wip/implementation-plan.md`):
//! - Position the proxy so guest egress cannot bypass it (network
//!   namespace/routing enforced at VM launch time, coordinated with
//!   `habitat-vm`).
//! - Default-deny ruleset with default allowlist entries (major AI
//!   provider APIs, standard package registries), read from the shared
//!   `policy/` location via `habitat-policy`, extensible via the checked-in
//!   config file.
//! - Filter at connection-setup destination inspection (e.g. SNI) -- never
//!   IP-based, never full TLS interception (AGENTS.md Section 2,
//!   invariants 6, 7).
//! - No plaintext secret/credential ever passed to the guest as an
//!   environment variable (AGENTS.md Section 2, invariant 5).
//!
//! No logic yet -- Phase 0 scaffolding only.
