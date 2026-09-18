//! `habitat-egress` -- the local proxy and default-deny allowlist
//! (design in `docs/decisions/0004-networking-layer.md`).
//!
//! - [`sni`]: extracts the SNI hostname from a guest's TLS ClientHello.
//! - [`dialer`]: seam between the proxy's decision logic and the outbound
//!   connection it opens, so it's testable over real loopback sockets.
//! - [`proxy`]: connection handler -- checks the SNI hostname against
//!   `habitat_policy::egress_allowlist` and relays or closes accordingly.
//!   No TLS termination in this path.
//! - [`dns`]: pins guest DNS resolution to a fixed upstream resolver so the
//!   network-layer restriction can't be bypassed via a default resolver.
//! - [`network_setup`]: builds the `podman run` network flags and nftables
//!   ruleset that make this proxy the only address the guest can reach.
//!
//! No plaintext secret or credential is ever passed to the guest as an
//! environment variable anywhere in this crate (`AGENTS.md` Section 2,
//! invariant 5).
//!
//! This crate doesn't cover booting a real guest through this
//! configuration and confirming allow/deny/bypass behavior from inside it
//! -- that needs real KVM, so it's `tests/manual/validate-egress.sh`'s
//! job. Everything else is exercised over real loopback sockets in this
//! crate's tests and `tests/adversarial/egress_bypass.rs`.

pub mod dialer;
pub mod dns;
pub mod network_setup;
pub mod proxy;
pub mod sni;
