# reviews/CHECKLIST.md -- Quarterly Governance Review

This is the **sole** governance artifact for Agent Habitat (AGENTS.md
Section 8). Do not create a second checklist, tracker, or process doc
covering any of the ground below -- if a new case needs tracking, add it
to this file.

**Cadence:** quarterly. The scheduled trigger that opens a tracking issue
for each pass lives at `.github/workflows/quarterly-review.yml`.

Each quarterly pass copies the template below into a new dated entry at
the bottom of this file, works through it, and leaves the filled-in record
in place (append-only history -- do not delete or overwrite a past entry).

---

## How to run a pass

1. Create a new entry using the template in "Entry template" below, dated
   `YYYY-QN`.
2. Work through all three sections for that entry: dependency/tool
   catalogue, allowlist/blocklist change log, containment policy
   accumulation.
3. Any item found to need a change (e.g. a stale dependency, an allowlist
   entry that should be removed) gets its own follow-up task -- link it
   rather than trying to resolve it inline during the review itself.
4. Commit the filled-in entry. The review is not complete until the entry
   is committed with all three sections addressed.

## Entry template

```
### YYYY-QN

Reviewed by: <name>
Date: YYYY-MM-DD

#### 1. Dependency / tool catalogue

- [ ] Podman version in use, and whether a newer stable release exists
- [ ] crun-krun / libkrun version in use
- [ ] passt version in use
- [ ] Rust toolchain / crate dependency audit (e.g. `cargo audit` output)
- [ ] Any dependency with a known CVE since the last pass, and its status

#### 2. Allowlist / blocklist change log

- [ ] Every egress allowlist change merged since the last pass, with
      justification
- [ ] Every secrets-blocklist change merged since the last pass, with
      justification
- [ ] Every git-history-toggle flip (default-off -> on) approved for a
      project since the last pass, with its logged approval entry linked
      (AGENTS.md Section 8 requires this to be logged *before* it takes
      effect -- this review confirms that actually happened, it does not
      substitute for it)

#### 3. Containment policy accumulation

- [ ] Resource-limit defaults (CPU/memory/disk caps) still reflect intended
      limits, no drift from ad-hoc per-session overrides
- [ ] No new live/continuous file-share or bridging mechanism has crept in
      (Section 2 invariant #1)
- [ ] No config path has been added that can disable containment,
      blocklist enforcement, or patch validation (Section 2 invariant /
      Phase 7 exit gate)
- [ ] Audit log coverage still spans session start/stop, preflight,
      VM launch/teardown, proxy decisions, and sync events with no gap
      introduced since the last pass

#### Outcome

Summary of findings and any follow-up tasks opened:
```

---

## Review history

(No passes recorded yet -- the first pass runs against the v1 ship
candidate, see the implementation plan's Phase 8 validation run-book.)
