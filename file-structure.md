# file-structure.md -- Repository Layout Conventions

This file codifies where things live in Agent Habitat. It exists so that
"where does X go" has one answer, checked against before any new top-level
directory is created. See `AGENTS.md` Section 6 for the rules this file
implements, and `docs/plan.md` for what each domain is responsible for.

## 1. Top-level layout

```
.
|-- Cargo.toml              # workspace root (Rust)
|-- crates/                 # all `habitat` code, one crate per domain
|   |-- cli/                # habitat-cli   -- the `habitat` binary entrypoint
|   |-- install/            # habitat-install -- `habitat install` + preflight checks
|   |-- workspace/          # habitat-workspace -- secrets blocklist, disk-build, two-point sync
|   |-- vm/                 # habitat-vm    -- containerd/nerdctl launch, Kata/Firecracker, session lifecycle
|   |-- egress/             # habitat-egress -- local proxy, default-deny allowlist enforcement
|   |-- audit/              # habitat-audit -- unified boundary audit log
|   `-- policy/             # habitat-policy -- shared config/policy schema types + loader (code)
|-- policy/                 # shared policy DATA: default blocklist, default egress allowlist,
|                            # resource-limit defaults. Read by both crates/workspace and
|                            # crates/egress via crates/policy -- never duplicated per-domain.
|-- docs/
|   |-- plan.md             # product source of truth (existing)
|   |-- diagrams/           # existing
|   `-- decisions/          # ADRs -- one file per decision, see Section 3 below
|-- reviews/
|   `-- CHECKLIST.md        # the one governance artifact (AGENTS.md Section 8)
|-- tests/
|   |-- unit/<domain>/      # mirrors crates/<domain>/, one dir per crate above
|   |-- integration/        # end-to-end: launch -> session -> teardown
|   `-- adversarial/        # containment-escape + egress-bypass tests, together
`-- .github/
    `-- workflows/          # CI + the quarterly-review scheduling trigger
```

## 2. Rules this layout enforces

- **Shared policy is not duplicated per-domain.** `policy/` (data) plus
  `crates/policy/` (the code that defines its schema and loads it) is the
  single place both the VM launcher (`crates/vm`) and the workspace/sync
  layer (`crates/workspace`) get their configuration from. Neither crate
  keeps its own copy of blocklist or allowlist defaults.
- **`docs/decisions/` holds ADRs**, including deferred-item design notes
  (AGENTS.md Section 4). Naming: `NNNN-short-title.md`, sequential, never
  renumbered or deleted -- a superseded ADR is marked superseded, not
  removed. `docs/decisions/template.md` is the starting point for a new one.
- **Test tree mirrors the source tree.** A change to `crates/egress/`
  expects a corresponding directory at `tests/unit/egress/`. Integration
  and adversarial tests are cross-cutting by nature, so they live in their
  own top-level test directories rather than under a single domain.
- **One governance file.** `reviews/CHECKLIST.md` is the sole tracked
  governance artifact -- do not create a second checklist, tracker, or
  process doc that covers the same ground (dependency/tool catalogue,
  allowlist/blocklist change log, containment policy accumulation). If an
  existing checklist needs a new case, edit it in place.

## 3. ADR conventions

- One decision per file, `docs/decisions/NNNN-short-title.md`.
- Use `docs/decisions/template.md` as the starting structure (Status,
  Context, Decision, Consequences).
- Status is one of: `proposed`, `accepted`, `superseded by NNNN`. Roadmap
  decisions that are foundational to v1 (e.g. host OS family is
  Fedora-based + Ubuntu-based in parallel, guest is fixed at a minimal
  Alpine image) are recorded as `accepted` from the start, per
  `docs/plan.md` and `AGENTS.md` Section 5. A decision that later changes
  is marked superseded, never edited in place or deleted.

## 4. What does NOT belong at the top level

- No second config/policy directory. If a domain seems to need its own
  policy file, that is a signal it belongs in the shared `policy/`
  location instead, loaded through `crates/policy`.
- No ad-hoc `scripts/` grab-bag for governance or scheduling -- the
  quarterly-review trigger lives in `.github/workflows/`, next to the rest
  of CI, not as a loose shell script elsewhere.
- No per-domain test directories nested inside `crates/*/tests` for the
  categories covered above -- unit tests may still live alongside their
  crate as normal Rust `#[cfg(test)]` modules for pure internal logic, but
  anything covering the domain's contract with the rest of the system
  (the cases enumerated in each phase's exit gate) belongs under
  `tests/unit/<domain>/` so it mirrors the source tree and stays
  discoverable from one place.
