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
  7) -- done: `egress_allowlist.txt` holds the default egress allowlist
  (major AI provider APIs, standard package registries, scoped to the v1
  AlmaLinux platform target), parsed by
  `crates/policy/src/egress_allowlist.rs` (baked into the binary via
  `include_str!`, same "not re-read from disk at runtime" contract as
  `blocklist.txt`) and extended per project via that project's checked-in
  config (`crates/policy/src/config.rs`'s `egress_allowlist_additions`,
  additive only). Matching is by destination hostname (exact, or `*.`
  subdomain-wildcard) only -- never IP-based, per `docs/decisions/
  0004-networking-layer.md`. `crates/egress`'s local proxy is what
  actually checks a guest connection's SNI hostname against it.
- **Content-based secrets scanning** (Betterleaks) -- done:
  `betterleaks-baseline.toml` holds the bundled baseline content-scan
  ruleset, parsed by `crates/policy/src/secrets_scan.rs` (baked into the
  binary via `include_str!`, same "not re-read from disk at runtime"
  contract as `blocklist.txt`) and merged, additively only, with a
  project's own `betterleaks.toml` (per-project extension mechanism
  named explicitly under `secrets_scan.content_rules_path` in the
  checked-in config, resolution order documented in `secrets_scan.rs`).
  `crates/workspace` is what actually shells out to the `betterleaks`
  binary against the merged result; nothing here runs a process.

Resource-limit defaults and the git-history toggle live in the
operator-facing checked-in config file (Phase 7), not here -- this
directory is for the security-relevant policy defaults that ship with
Agent Habitat itself, not per-project runtime configuration.
