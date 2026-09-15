# 0006. Distribution/packaging layer: `habitat` ships as prebuilt host binaries, not built from source by operators

Status: accepted
Date: 2026-09-14

## Context

`habitat` is a compiled Rust binary (`crates/cli`), but nothing in this
repo had settled how an operator actually gets that binary onto their
machine. The only path that existed by construction was cloning this repo
and running `cargo build` themselves, which would make a Rust toolchain
(rustc/cargo, and implicitly a version compatible with the checked-in
`Cargo.lock`) a real prerequisite on every host that runs `habitat` --
alongside the four runtime prerequisites `habitat install`/`habitat run`'s
preflight already check (host OS, KVM -- `0001-host-os-layer.md`; Podman,
krun-runtime -- `0003-container-engine-runtime-layer.md`).

That would sit awkwardly next to the project's own stated posture: a
"single hardened setup" (`docs/plan.md` Section 2.5) that keeps the
host's installed footprint to what's strictly needed to launch and
contain a session. A full build toolchain is a meaningfully larger,
unrelated piece of software to trust on a production host, purely to
produce a binary that doesn't itself need it to run.

Rust/cargo are also categorically different from the four checks in
`checks.rs`: those are runtime prerequisites the already-compiled
`habitat` binary verifies about the machine it's executing on. A
toolchain check would be checking how `habitat` itself came to exist,
which is meaningless to ask from inside a binary that, by virtue of
running at all, was already built somewhere.

## Decision

`habitat` ships as prebuilt binaries (and, ultimately, native packages --
`.rpm` for AlmaLinux (v1) and Fedora (v1.1), `.deb` taken up when Ubuntu
(v2) starts, matching `0001-host-os-layer.md`'s sequential platform
roadmap) that operators install directly. Building `habitat` from source
stays possible for contributors working on this repo, but is never the
expected path for an operator running sandboxed sessions, and rustc/cargo
are never added to `habitat install`'s or `habitat run`'s preflight
checks.

## Consequences

- The host prerequisite list for *running* `habitat` stays exactly the
  four checks already in `checks.rs` (host OS, KVM, Podman, krun-runtime)
  -- no Rust toolchain requirement is added alongside them.
- A release/packaging pipeline (building and publishing binaries or
  `.rpm` packages for v1/v1.1, later `.deb` packages for v2, on tagged
  releases) becomes a required piece of project infrastructure that does
  not yet exist and needs its own design -- tracked as Phase 9 in
  `tmp/wip/implementation-plan.md`, sequenced after the Phase 8 validation
  gate rather than folded into it.
- Contributor-facing build instructions (rustc/cargo version, `cargo build
  --release`) belong in repo documentation for people working on `habitat`
  itself, not in any operator-facing preflight or install-checklist
  output.
- Versioning and upgrade handling for prebuilt binaries/packages (how an
  operator moves from one `habitat` version to the next) is not addressed
  by this decision and remains open.
