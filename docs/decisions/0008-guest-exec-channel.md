# 0008. Guest exec channel: per-session SSH over the passt network, not `podman exec`

Status: accepted
Date: 2026-09-15

## Context

Phase 4's two-point sync mechanism (`crates/workspace::sync`,
`guest_exec::GuestExecRunner`) was built entirely on `podman exec` to run
`git status`/`git add`/`git commit`/`git apply` inside the running guest,
and `podman cp` to copy a patch file in. Every test for that mechanism
mocks the `CommandRunner` seam, so nothing exercised this against a real,
booted `krun` guest until a real run of `tests/manual/validate-vm-launch.sh`
did, and hit:

```
the handler does not support exec
```

This is not a bug in this project's setup. It is a real, currently
unresolved limitation of the `krun` OCI runtime (backed by libkrun):
there is no existing mechanism for injecting a new process into an
already-running microVM the way `exec` does for a namespace-based
container. This is confirmed by the runtime's own maintainers -- see
[containers/crun#2090, "Support podman exec in krun"](https://github.com/containers/crun/issues/2090)
("the krun backend does not support exec for 'obvious' reasons -- there
is no existing mechanism for launching executables into the microVM")
and [containers/crun#1098](https://github.com/containers/crun/issues/1098).
Both are open and unimplemented as of this decision. `podman exec`
against a `krun`-runtime container fails unconditionally, on any host,
with any `crun-krun`/libkrun version available today -- this is not a
version-pinning or flag problem to work around.

`0003-container-engine-runtime-layer.md`'s choice of rootless Podman +
`krun` remains sound for launch/teardown (`crates/vm::launcher` never
used `exec`, only `run`/`rm`, and that half is validated). The gap is
narrower and specific: Phase 4 needs *some* way to run commands inside a
live guest, and `podman exec` cannot be it.

## Decision

The guest exec channel is SSH, over the same `passt`-provided network
interface Phase 5's egress proxy already requires (`docs/decisions/
0004-networking-layer.md`) -- not a custom protocol, and not a revisit of
the container engine/runtime choice itself.

- The guest image (`guest/Containerfile`, fixed Alpine per
  `0002-guest-os-layer.md`) runs `sshd`, started by a small entrypoint
  script rather than the image's prior `sleep infinity` placeholder.
  `PasswordAuthentication` and root login are both disabled; the only
  account is a dedicated, unprivileged `habitat` user.
- Each session gets a fresh ed25519 keypair, generated on the host at
  launch time (`habitat_vm::guest_ssh`), never reused across sessions.
  The private key never leaves the host and is deleted at teardown,
  alongside the rest of the session's disposable state
  (`0005-storage-layer.md`'s same disposability principle, applied here
  to a credential rather than a disk). The public key is **not** a
  secret -- passing it into the guest via a plaintext environment
  variable (`HABITAT_AUTHORIZED_KEY`, read by the guest's entrypoint
  script into `~/.ssh/authorized_keys`) does not violate `AGENTS.md`
  Section 2 invariant 5, which is about credentials and API keys;
  an SSH public key is precisely the half of an asymmetric keypair meant
  to be exposed.
- `habitat_vm::launcher` resolves the guest's address after launch (best
  current understanding: `podman inspect`'s network-settings output for
  the session; **not yet confirmed against real crun-krun/pasta output
  shape** -- same "confirm or correct on real hardware" position as
  `WORKSPACE_DISK_ANNOTATION`, see `tests/manual/validate-vm-launch.sh`).
  `crates/workspace::guest_exec::GuestExecRunner` shells out to the real
  `ssh`/`scp` binaries against that address and the session's private
  key, replacing its previous `podman exec`/`podman cp` argv construction
  while keeping the same `.exec()`/`.exec_with_env()`/`.copy_in()` call
  shape `crates/workspace::sync` already uses -- this is a channel swap
  under an unchanged sync design, not a redesign of Phase 4's sync logic
  itself.
- OpenSSH concatenates every argument after the destination into one
  string and hands it to the guest's login shell -- unlike `podman
  exec`'s pure-argv model, a value is exposed to shell interpretation on
  the remote end. Every token (program name, each argument, each env
  assignment's value) is shell-quoted (`guest_exec::shell_quote`, the
  standard `'...'`-with-escaped-embedded-quotes technique) before being
  joined, so this channel keeps the same "never let an untrusted or
  structured string reach a shell unescaped" posture the rest of this
  project already holds (`habitat-audit`'s JSON escaping, the blocklist
  matcher).

## Consequences

- This is a real cost, named rather than hidden: the guest now runs a
  listening network service (`sshd`) where `podman exec` required none
  at all. Mitigated by key-only auth, no root login, a single
  unprivileged account, and the fact that this service is reachable only
  from the host over the `passt`-provided local interface -- never
  exposed further, and never through Phase 5's egress proxy (see below).
- **This is not "guest egress."** Phase 5's default-deny, SNI-based
  allowlist (`0004-networking-layer.md`) governs the guest's own
  *outbound* connections leaving through `passt` to the wider network.
  SSH here is the reverse direction -- host-initiated, inbound to the
  guest, over the same physical interface but a different traffic
  direction entirely. It must never be routed through, or evaluated
  against, the egress allowlist; the two are unrelated questions that
  happen to share one network interface.
- `crates/workspace::guest_exec` and `crates/workspace::sync` change
  their guest-reaching mechanism but not their design: still one
  discrete invocation per guest interaction, still no long-lived
  connection or background process (`AGENTS.md` Section 2, invariant 1) --
  an SSH command that returns is exactly as discrete as a `podman exec`
  that returns.
- `ssh`/`scp` join `git`, `mke2fs`, and `debugfs` as host-side tools this
  project assumes are present rather than preflight-checking for
  (`crates/install::checks` does not check for `git` either) -- a gap
  worth closing when `habitat install`'s check list is next revisited,
  not a blocker for this decision.
- `tests/manual/validate-vm-launch.sh`, `validate-sync.sh`, and
  `validate-egress.sh` all update their guest-interaction steps from
  `podman exec` to SSH, since every one of them was silently relying on
  a mechanism that never worked in the first place.
