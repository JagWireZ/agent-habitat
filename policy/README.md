# policy/ -- shared policy data

This directory holds the actual default policy data, loaded through the
`habitat-policy` crate (`crates/policy/`) and consumed by both the
workspace/sync layer (`crates/workspace/`) and the egress proxy
(`crates/egress/`) -- never duplicated into either of those crates
directly. See `file-structure.md` Section 2.

Not yet populated -- this is Phase 0 scaffolding. Populated in:

- **Phase 2** (`docs/plan.md` Section 2.2 / AGENTS.md Section 2 invariant
  2): the secrets blocklist defaults (`.env`, `*.pem`, `*.key`, `id_rsa*`,
  cloud credential file patterns) and its documented per-project
  extension mechanism. This list is explicitly separate from
  `.gitignore` and never derived from or merged with it.
- **Phase 5** (`docs/plan.md` Section 2.3 / AGENTS.md Section 2 invariant
  7): the default egress allowlist (major AI provider APIs, standard
  package registries).

Resource-limit defaults and the git-history toggle live in the
operator-facing checked-in config file (Phase 7), not here -- this
directory is for the security-relevant policy defaults that ship with
Agent Habitat itself, not per-project runtime configuration.
