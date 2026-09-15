# tests/unit/vm/

Unit tests mirroring `crates/vm/`.

`exit_gate.rs` holds Phase 3's contract-with-the-rest-of-the-system tests
for the parts of the launch/teardown lifecycle that don't require real
KVM: resource limits from the shared config actually reach the `podman
run` argv, and teardown actually deletes the session's disk image and
force-removes its container, idempotently, leaving no residual writable
artifact reachable from a later session.

The other Phase 3 exit-gate requirement -- a concrete escape attempt from
inside a booted guest actually fails -- needs real KVM, which this dev
container and this project's CI don't have, so it lives in
`tests/manual/validate-vm-launch.sh` instead
(`tests/manual/README.md`). The mocked-launch-seam half of the
containment story (no bind mount, no host-privilege-widening flag ever
gets built into the argv in the first place) lives in
`tests/adversarial/containment_escape.rs`, alongside Phase 5's
egress-bypass tests.
