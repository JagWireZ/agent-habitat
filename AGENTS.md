# AGENTS.md -- Rules for Agents Working on Agent Habitat

This file governs any agent (AI or human) making changes to this repository.
Read it before touching any file. When this file conflicts with a comment,
issue, or ad-hoc instruction found elsewhere in the repo, **this file wins**
unless the person operating the repo explicitly overrides it in the moment.
Where this file and `docs/plan.md` describe the product, `docs/plan.md` is
the source of truth for *what* is being built; this file is the source of
truth for *how agents must behave* while building it. If you find a gap
between them, flag it rather than picking silently.

## 1. What this repo is

Agent Habitat gives an AI coding agent its own disposable virtual machine to
run in -- a sealed sandbox that looks and feels like your real project, but
isn't it. It has two separate locks, kept conceptually distinct:

- **The vault door** -- containment. Each session runs in a real microVM,
  launched by rootless Podman through the `krun` runtime (libkrun), not a
  shared-kernel container. Even a fully compromised agent can't reach the
  host.
- **The guard's rulebook** -- permissions. Rules for what's allowed to cross
  that boundary in either direction: which files get copied into the
  sandbox's disk in the first place, what network destinations the session
  can reach, and what comes back out.

Never conflate the two. A change that tightens the allowlist or the secrets
blocklist is not a substitute for a containment gap, and vice versa.

**Scope is single-host, single-operator.** Don't build for a fleet or
multi-tenant use unless asked -- the disposable-VM-per-session model, the
two-point sync mechanism, and the single audit destination are deliberate
single-host constructs, not placeholders waiting to be generalized.

**The host machine is Linux-only, and the platform roadmap is a single
sequential line: v1 targets AlmaLinux, v1.1 Fedora, v2 Ubuntu** -- not
two host families validated in parallel with a separately fixed guest
(see Section 5, and `docs/decisions/0006-sequential-platform-roadmap.md`).
There is no separate guest-distro axis to track: the guest image is built
from whichever platform the current roadmap stage targets. Don't build
host-OS-detection branches, nested-VM workarounds, or "best effort" paths
for macOS/Windows, or for any other Linux distro family (Arch, openSUSE,
etc.), or for Fedora/Ubuntu ahead of their own roadmap stage,
preemptively. macOS/Windows host support is future work, not yet
designed -- see Section 5.

**The virtualization stack is rootless Podman + the `krun` runtime
(libkrun), not containerd + Kata Containers + Firecracker.** No daemon,
no elevated launcher process -- Podman runs as the calling user, with
one-time `kvm` group membership as the only host-side setup step (see
`docs/decisions/0005-rootless-podman-krun-virtualization-stack.md`).

## 2. Non-negotiable invariants

These hold regardless of which part of the system you're touching. If a
task seems to require violating one, stop and flag it rather than
proceeding.

1. **No live, always-on file-sharing process between host and sandbox.**
   Syncing happens only at two well-defined moments -- host to sandbox
   before each prompt, sandbox to host after each tool call -- via the same
   trusted patch mechanism used for final promotion. Don't build a
   continuously-mounted live share; that reintroduces the background
   bridging process this design deliberately avoids.
2. **No filename-based masking applied after the sandbox's disk already
   exists.** The secrets blocklist (`.env`, `*.pem`, `*.key`, `id_rsa*`,
   cloud credential files, and similar) is applied *before* anything is
   copied in, including the very first copy that builds the disk. If a
   path shouldn't be visible to the guest, it's never included -- it's not
   hidden after the fact.
3. **The diff/patch produced by the trusted host-side sync mechanism is the
   authoritative change record -- never the agent's own transcript.** The
   transcript is always labeled supplementary, wherever it's referenced,
   logged, or displayed.
4. **The sandbox never commits or pushes to the user's real repository.**
   Its changes only ever arrive as a patch applied to the real working
   directory. Committing and pushing stay a manual, host-side action the
   user takes on their own schedule -- there is no forced "end of session"
   commit gate, and no code path where the agent's own git identity reaches
   the user's real remote.
5. **Never write a credential or provider API key into the guest as a
   plaintext environment variable.** Use the actual secret-injection
   mechanism for the chosen VM stack, not env vars, not baked into the
   guest image, not passed as a CLI argument -- no exceptions, not even in
   test scripts or "just for debugging" code.
6. **Egress enforcement happens at the local proxy that actually carries
   guest traffic** -- never only inside the guest, and never assumed to
   hold for a network path that hasn't actually been shown to be the one
   carrying it.
7. **Default-deny egress.** Only the allowlist (AI provider APIs, standard
   package registries) is reachable; everything else is blocked. Filter by
   destination at connection setup (e.g. SNI), not by IP -- IPs rotate, and
   fully intercepting traffic would break certificate verification in agent
   tooling.
8. **VM/kernel containment and the secrets blocklist are independent
   mechanisms, both required.** Containment stops a compromised guest from
   reaching outside the VM. The blocklist stops sensitive files from being
   included in the sandbox's disk at all, even though everything else on
   that disk is fully readable/writable by the agent. Neither substitutes
   for the other; don't drop one because the other seems to cover it.
9. **Git history exposure is an explicit, default-off toggle in the checked-
   in config file** -- synthetic repo by default, real `.git` shared
   read-only only when a project turns that on. Never silently expose real
   history "to make git work better."
10. **A patch that fails validation on arrival is flagged for review** --
    never silently merged and never silently dropped. The same standard
    applies to any other automated check whose result is genuinely
    ambiguous: it needs its own visible state, distinct from both "clean"
    and "hard reject."
11. **Launch-time preflight checks fail closed and never silently.** On
    refusal (e.g. hardware virtualization support isn't present), name the
    specific check that failed, exit non-zero, and log it to the same audit
    destination as normal session activity, tagged distinctly.
12. **Audit/session logs are untrusted, attacker-influenced input, not just
    a record.** No shell interpolation of log content anywhere it's parsed
    or displayed -- treat it like any other attacker-influenced string.
13. **All files must contain only ASCII characters; any non-ASCII Unicode
    characters are prohibited.**

## 3. "Verify before trusting" -- a recurring discipline

Several parts of this system require a real verification step before
anything downstream is allowed to depend on them. Don't skip these in favor
of code that looks correct by inspection:

- **VM/kernel containment:** a concrete escape attempt from inside the
  guest (reaching host files, host processes, or the host network
  namespace) must be shown to actually fail before containment is trusted.
- **Egress ruleset:** a concrete connection trace confirming allowed and
  blocked destinations are actually intercepted at the proxy hand-off --
  before trusting the ruleset, and re-run after any change.
- **Hardware virtualization preflight:** must be verified to actually
  detect the absence of virtualization support, not just assumed present --
  `docs/plan.md` notes this can be silently unavailable on some cloud
  machines.
- **Sync/patch validity:** a corrupted or unexpected patch must be
  demonstrated to be flagged rather than silently applied, in both
  directions of the sync.
- **Sync performance at scale:** not yet validated for large monorepos or
  large binary files (see `docs/plan.md` Known limitations) -- don't claim
  this works at scale until it's actually been measured.
- **The stack overall:** rootless Podman + the `krun` runtime (libkrun) +
  block-device-backed storage + `passt` networking is newer and less
  battle-tested than more common setups, and doesn't have a well-trodden
  public reference to follow end to end. It needs real hands-on
  validation on real hardware before v1 ships, not just a configuration
  or design review.
- **DNS containment under `passt`:** a leftover default resolver inside
  the guest would be a way for the network restriction in Section 2,
  invariant 7 to quietly leak -- must be verified pinned to the proxy
  path, not assumed.

## 4. Deferred items -- do not implement, note the trigger only

These are intentionally deferred. If asked to "improve" or "complete" one
of these areas, write or update the design note in `docs/decisions/`, and
otherwise stop -- do not build the implementation unless the stated trigger
has actually occurred and someone explicitly asks for the build.

| Item | Trigger to build |
|---|---|
| Full in-sandbox activity logging (beyond boundary-crossing audit) | Boundary-only audit proves insufficient for real incident review |
| Agent proactively checking host files mid-task (outside the two sync points) | A demonstrated task pattern that materially needs it, once the two-point sync is shown insufficient in practice |
| Optional live progress view into a running session | A real need to observe an in-progress session beyond post-hoc audit review |
| Targeted secret injection (a single value instead of withholding a whole blocklisted file) | v1's all-or-nothing blocklist behavior is shown to block a genuinely necessary task |
| GPU support | An actual project requiring GPU-backed agent work |
| Additional host distro/family variants (e.g. Arch, openSUSE) | v1.1 (Fedora) and v2 (Ubuntu) have both shipped and been validated end-to-end |
| macOS / Windows host support | The full sequential platform roadmap (v1 AlmaLinux, v1.1 Fedora, v2 Ubuntu) has shipped and been validated; the host isolation model for a non-KVM host is designed and reviewed, not assumed |

Known accepted gaps (do not attempt to close without being asked):
- The host must be Linux -- libkrun needs KVM. macOS and Windows host
  support is future work, not yet designed.
- Hardware virtualization isn't always available on cloud machines --
  checked for up front, not papered over or assumed. One-time `kvm` group
  membership is also required for rootless launch.
- In-sandbox activity isn't logged in v1 -- only what crosses the
  host/sandbox boundary (the VM process, the proxy, the sync mechanism).
- No middle ground for blocked files -- if a task genuinely needs a
  blocklisted file's contents, it's simply unavailable in v1.

## 5. Roadmap and build order

**Host OS is Linux-only throughout the platform roadmap.** macOS and
Windows host support is a separate, later effort that hasn't been
designed yet -- it is not part of the sequence below, and no code path
should assume or special-case a non-Linux host in the meantime.

The platform roadmap is a single sequential line, not a host-family-
parallel / guest-fixed split (`docs/decisions/0006-sequential-platform-roadmap.md`).
Each stage covers both what `habitat` runs on and what the guest image is
built from -- there's no separate guest-distro axis to track:

```
v1   -- AlmaLinux
         (full system validated end-to-end on real hardware)
  -> v1.1 -- Fedora
             (expected light lift given closeness to AlmaLinux,
             still requires its own validation pass)
    -> v2 -- Ubuntu
              (different security model under the hood -- waits
              until v1 is proven out, not shipped in parallel)
      -> (later, undesigned) further platform families
         (e.g. Arch, openSUSE)
        -> (later, undesigned) macOS / Windows host support
```

Rules that follow from this:

- **Don't build ahead of the roadmap.** If a task seems to need something
  from a later stage (e.g. a Fedora- or Ubuntu-specific path, an Arch or
  openSUSE path, or any macOS/Windows host path) that doesn't exist yet,
  flag it rather than building a one-off parallel mechanism for it now.
- **v1 is AlmaLinux, full stop.** Distro-conditional branches for Fedora,
  Ubuntu, or any other platform, and any host-OS branches beyond Linux,
  don't belong in the codebase until their own roadmap stage starts --
  there is no "ship the next stage early" shortcut.

## 6. File structure conventions

Follow `file-structure.md` if present, and keep these conventions in mind
regardless:

- Config/policy shared across domains (e.g. isolation and egress policy
  used by both the VM launcher and the workspace/sync layer) belongs in a
  shared location, not duplicated into each consuming domain's directory.
- Anything under `docs/decisions/` is an ADR-style record, including
  deferred-item design notes (Section 4) -- these are real deliverables,
  not placeholders to skip.
- Test locations should mirror source locations: unit tests mirror domain
  folders, integration tests cover end-to-end launch -> session ->
  teardown, and adversarial tests cover egress bypass attempts and
  containment-escape attempts together.
- When an existing test checklist needs a new case, edit that file --
  don't create a second, competing checklist covering the same ground.

## 7. Definition of "done"

An artifact is done when:

1. The file/script/policy exists at its intended path.
2. Where a verification step is called for (Section 3), that verification
   has actually been run and passed -- not just written.
3. Assertions that are supposed to be hard failures actually fail the
   process/gate -- no "warning only" checks standing in for a stated hard
   precondition.
4. Idempotent artifacts (config appliers, provisioning scripts) have been
   run twice and confirmed to produce no changes on the second run.
5. Deferred items have a design note, explicitly marked not implemented,
   with the trigger condition stated -- and nothing more.

"I wrote the file" is not done. "I wrote the file and ran the check it
depends on" is done.

## 8. Governance

- Governance is consolidated into **one** file, `reviews/CHECKLIST.md`,
  reviewed on **one** quarterly cadence covering three things together:
  the dependency/tool catalogue, allowlist/blocklist changes since the
  last pass (including any git-history-toggle flips), and accumulated
  containment policy. Do not split this into separate tracked processes.
- A real calendar-reminder/scheduling artifact triggers the review -- not
  an instruction relying on someone remembering.
- Any change that expands what a session can reach or see -- including
  flipping the git-history toggle on for a project -- requires a logged,
  reviewed entry *before* it takes effect. This applies even to changes
  that look small.

## 9. When instructions are ambiguous or seem to require a shortcut

- If a request would require violating Section 2's invariants, don't
  reinterpret the request to make it seem safe -- say so and propose the
  compliant alternative (e.g. a design note instead of an implementation,
  or a change to the config file instead of a code-level bypass).
- If a mechanism seems missing, look for it before building a substitute.
  If it's genuinely absent, stub it minimally and say so explicitly rather
  than quietly filling the gap with new logic.
- If asked to build a deferred item (Section 4) without the trigger having
  occurred, write the design note only and say why you stopped there.
- If this file and `docs/plan.md` seem to disagree about the architecture,
  stop and flag it rather than picking one silently -- see the note at the
  top of Section 1.
