# policy/ -- shared policy data

This directory holds the actual default policy data, loaded through the
`habitat-policy` crate (`crates/policy/`) and consumed by both the
workspace/sync layer (`crates/workspace/`) and the egress proxy
(`crates/egress/`) -- never duplicated into either of those crates
directly. See `file-structure.md` Section 2.

Populated so far:

- **Phase 2** (`docs/plan.md` Section 2.2 / AGENTS.md Section 2 invariant
  2) -- done: `blocklist.txt` holds the secrets blocklist defaults
  (`.env`, `*.pem`, `*.key`, `id_rsa*`, cloud credential file patterns),
  parsed by `crates/policy/src/blocklist.rs` (baked into the binary via
  `include_str!`, not re-read from disk at runtime) and extended per
  project via that project's checked-in config
  (`crates/policy/src/config.rs`'s `blocklist_additions`, additive only).
  This list is explicitly separate from `.gitignore` and never derived
  from or merged with it.
- **Phase 5** (`docs/plan.md` Section 2.3 / AGENTS.md Section 2 invariant
  7) -- not yet populated: the default egress allowlist (major AI
  provider APIs, standard package registries).

Resource-limit defaults and the git-history toggle live in the
operator-facing checked-in config file (Phase 7), not here -- this
directory is for the security-relevant policy defaults that ship with
Agent Habitat itself, not per-project runtime configuration.
