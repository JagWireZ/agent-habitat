//! `habitat-egress` -- the local proxy and default-deny allowlist
//! (Phase 5, `tmp/wip/implementation-plan.md`; design in
//! `docs/decisions/0004-networking-layer.md`).
//!
//! - [`sni`]: extracts the SNI hostname from a guest's TLS ClientHello --
//!   the destination-inspection primitive everything else here acts on.
//!   Pure parsing, no network I/O.
//! - [`dialer`]: the seam between the proxy's decision logic and the
//!   outbound connection it opens to an allowed destination, so that
//!   logic is testable over real loopback sockets without a real
//!   destination host on the network.
//! - [`proxy`]: the actual connection handler -- read the ClientHello,
//!   check the SNI hostname against `habitat_policy::egress_allowlist`,
//!   relay bytes to the real destination on an allow, close the
//!   connection on a deny. No TLS termination anywhere in this path --
//!   certificate verification in guest tooling runs unmodified,
//!   end-to-end.
//! - [`dns`]: pins guest DNS resolution to this proxy's own path by
//!   forwarding queries to a fixed upstream resolver, so the network-
//!   layer reachability restriction below can't be quietly bypassed via
//!   a leftover default resolver (`0004`'s open item).
//! - [`network_setup`]: pure construction of the `podman run` network
//!   flags (switching the guest onto a real `passt`-backed interface
//!   instead of libkrun's default TSI mode, and pinning its DNS to this
//!   proxy) and the nftables ruleset that makes this proxy the *only*
//!   address the guest can reach at all -- coordinated with
//!   `habitat-vm::launcher` at launch time.
//!
//! No plaintext secret or credential is ever passed to the guest as an
//! environment variable anywhere in this crate (`AGENTS.md` Section 2,
//! invariant 5) -- there is no code path here that sets one; targeted
//! secret injection is an explicitly deferred AGENTS.md Section 4 item,
//! not something this phase implements.
//!
//! **What this crate does not (yet) cover:** actually booting a guest
//! through the `pasta`/firewall configuration built here and confirming,
//! from inside it, that an allowlisted destination succeeds, a denied
//! one is blocked, and a direct-IP or DNS-bypass attempt is blocked too
//! -- that needs real KVM this dev container and this project's CI don't
//! have, so it's `tests/manual/validate-egress.sh`'s job. Everything in
//! this crate that doesn't require an actually-booted guest (the
//! allow/deny decision itself, the relay, the DNS forwarder, the argv/
//! ruleset construction) is exercised for real -- over real loopback
//! sockets, not mocked -- in this crate's own tests and
//! `tests/adversarial/egress_bypass.rs`.

pub mod dialer;
pub mod dns;
pub mod network_setup;
pub mod proxy;
pub mod sni;
