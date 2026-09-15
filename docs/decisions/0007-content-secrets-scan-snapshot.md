# 0007. Content-based secrets scanning: ruleset snapshot taken once at session start, never re-read on sync

Status: accepted
Date: 2026-09-15

## Context

Content-based secrets scanning (Betterleaks, `habitat_policy::secrets_scan`,
`crates/workspace::content_scan`) merges a bundled baseline ruleset with an
optional project-supplied `betterleaks.toml`. That project file, when it
lives inside the mounted project tree (the default resolution path -- see
`secrets_scan::resolve_project_rules_path`), is also something the agent
can edit mid-session, the same as any other file in the sandbox.

If the effective ruleset were re-resolved from disk on every host<->sandbox
sync, an agent could weaken its own `betterleaks.toml` mid-session (e.g.
widen an allowlist, though `secrets_scan::merge_rules` already refuses the
crudest version of this -- see the Known limitation below) and have that
weaker ruleset take effect on the very next sync, silently lowering the bar
for what content scanning catches for the rest of the session. That is the
same category of problem AGENTS.md Section 2 invariant 10 and `docs/plan.md`
Section 2.2 already solve for sync patches in general ("a patch that fails
validation is flagged for review, never silently merged") -- this decision
is that same posture applied specifically to the one file that governs
scanning itself, which is boundary-relevant in a way an ordinary file edit
isn't, even though it looks like one.

**Important scoping note:** the two-point host<->sandbox sync mechanism
this decision partly depends on (Phase 4 of
`tmp/wip/implementation-plan.md`, `docs/plan.md` Section 2.2) is not built
yet -- only the Phase 2 disk-build pipeline (a single, one-shot build) 
exists today. Per AGENTS.md Section 9 ("if a mechanism seems missing, look
for it before building a substitute... stub it minimally and say so
explicitly"), this ADR records the intended design for the sync-dependent
half of this feature rather than building a parallel, ad-hoc sync/patch
mechanism to enforce it early. The trigger to implement that half is
**Phase 4 landing** -- see Consequences below for exactly what it needs to
call.

## Decision

1. **Snapshot once, at session start, before the first disk image is
   built.** `crates/workspace::pipeline::build` resolves and merges the
   effective content-scan ruleset exactly once per build
   (`habitat_policy::secrets_scan::load_effective_ruleset`), writes it to
   `BuildRequest::content_ruleset_path`, and every content scan for that
   build reads from that written snapshot file, never re-resolving from
   the project's live `betterleaks.toml`. This is implemented today.
2. **A later sandbox->host sync must not silently update the governing
   snapshot.** Once Phase 4 exists, if a sync patch touches
   `betterleaks.toml`, that patch must be routed through the same "flagged
   for review, not silently merged" path every other sync patch already
   goes through (`docs/plan.md` Section 2.2), *and* the governing
   in-memory/on-disk snapshot (`content_ruleset_path`'s contents) must not
   be updated as a side effect of applying that patch, even if the patch
   itself validates structurally. Re-resolving the effective ruleset for a
   session is a deliberate, explicit action (e.g. a fresh session start),
   never an implicit consequence of an ordinary sync.
3. **A distinct audit event for this specific file's mid-session edit.**
   `habitat_audit::EventKind::ContentRulesetMidSessionEdit` exists today
   (added by this change) precisely so Phase 4's sync-validation code has
   a ready-made, distinctly-tagged event to emit the moment it detects a
   patch touching `betterleaks.toml` -- distinguishing this from an
   ordinary file edit in the audit trail, per this decision's Context.

## Consequences

- Phase 2's one-shot pipeline already satisfies point 1 in full: nothing
  further is needed there.
- **Implementation note (2026-09-15):** Phase 4 has landed
  (`crates/workspace/src/sync.rs`) and implements all four bullets below
  in full -- `sync::non_structural_gate` detects a `betterleaks.toml`-
  touching patch by basename via `patch::touches_content_ruleset_file`
  and routes it to `FlagReason::ContentRulesetMidSessionEdit`
  unconditionally (before the structural check even runs);
  `sync::emit_flagged` always emits `EventKind::SyncFlagged` and
  `EventKind::ContentRulesetMidSessionEdit` together, never one instead
  of the other; and `content_ruleset_path` (`pipeline::BuildRequest`) is
  never written to anywhere in `sync.rs`, so a flagged edit cannot update
  the governing snapshot even as a side effect. Pinned by
  `tests/adversarial/sync_patch_validation.rs::host_to_sandbox_flags_a_betterleaks_toml_edit_and_emits_the_distinct_audit_event`.
  Applied symmetrically to the host->sandbox direction too, since a
  ruleset edit is boundary-relevant regardless of which side it
  originates from, even though this ADR's own scope was the
  sandbox->host case.
- Phase 4's original description, kept for history:
  - Detect when an incoming sandbox->host patch touches `betterleaks.toml`
    (by path, not by content-diffing -- the file's mere presence in the
    patch is what matters here, regardless of what changed).
  - Route that patch through the existing bad-patch-flagged-for-review
    state (AGENTS.md Section 2 invariant 10) rather than the ordinary
    clean-apply path, even if the patch is otherwise structurally valid.
  - Emit `EventKind::ContentRulesetMidSessionEdit` when it does, in
    addition to (not instead of) whatever the ordinary sync-event audit
    trail already records for that sync.
  - Leave the session's governing ruleset snapshot untouched until an
    operator deliberately starts a new session (or otherwise explicitly
    re-triggers ruleset resolution) -- never as an automatic effect of the
    flagged patch being reviewed or approved.
- **Known limitation, not yet closed by this decision:** `secrets_scan
  ::merge_rules` already rejects the crudest ruleset-weakening attempt (a
  catch-all `[allowlist]` regex) at merge time, and the baseline is always
  present in the merged result regardless of what a project supplies. A
  more surgical allowlist-narrowing edit that stays within that guard is
  not detected as an attack by that function -- this ADR's snapshot-once
  behavior is what prevents such an edit from taking effect *mid-session*,
  not `merge_rules` itself; a genuinely malicious project ruleset checked
  in from the start remains a governance question for
  `reviews/CHECKLIST.md` (AGENTS.md Section 8), not a runtime one.
- This ADR does not change `tmp/wip/implementation-plan.md`'s Phase 4 exit
  gate, which already covers "a crafted sync patch attempting to smuggle a
  blocklisted file back in is caught by the re-check" -- it adds the
  `betterleaks.toml`-specific requirements above to that same phase's
  scope rather than opening a new phase.
