//! Phase 5's adversarial coverage of the egress path -- the part of "a
//! non-allowlisted destination, an allowlist-lookalike, and a direct-IP
//! bypass are all blocked" that can actually be checked without an
//! actually-booted guest: that the proxy's decision logic and the
//! network/firewall configuration this crate builds never leave a gap a
//! crafted destination could slip through.
//!
//! This deliberately does **not** claim to be the exit gate's real
//! connection trace -- confirming the `pasta` interface and nftables
//! ruleset actually restrict a booted guest's reachability, including
//! that DNS can't be used to route around it, needs real KVM neither
//! this dev container nor this project's CI has. That real trace is
//! `tests/manual/validate-egress.sh`'s job (see `tests/manual/README.md`
//! and `file-structure.md`, which puts Phase 3's containment tests and
//! Phase 5's egress-bypass tests together here and in `tests/manual/`).

use habitat_audit::MemoryAuditSink;
use habitat_egress::dialer::testing::FakeDialer;
use habitat_egress::sni::testing::build_client_hello;
use habitat_egress::{network_setup, proxy};
use habitat_policy::egress_allowlist;
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;

fn connect_and_send(addr: SocketAddr, bytes: &[u8]) -> TcpStream {
    let mut guest = TcpStream::connect(addr).unwrap();
    guest.write_all(bytes).unwrap();
    guest.shutdown(Shutdown::Write).unwrap();
    guest
}

fn deny_check(sni_host: &str, entries: &[String]) -> proxy::ConnectionOutcome {
    let dialer = FakeDialer::default(); // no routes -- any dial attempt is itself a failure
    let audit = MemoryAuditSink::default();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hello = build_client_hello(sni_host);
    thread::spawn(move || {
        connect_and_send(addr, &hello);
    });
    let (client, _) = listener.accept().unwrap();
    let outcome = proxy::handle_connection(client, entries, &dialer, &audit).unwrap();
    assert!(
        dialer.attempts.borrow().is_empty(),
        "a denied SNI host must never trigger an outbound dial: {sni_host:?}"
    );
    outcome
}

/// A crafted hostname built specifically to look like it should match a
/// wildcard default-allowlist entry (`*.githubusercontent.com`) without
/// actually being a subdomain of it -- the classic "suffix, not
/// subdomain" confusion attack.
#[test]
fn a_wildcard_lookalike_hostname_is_denied_against_the_real_default_allowlist() {
    let entries = egress_allowlist::default_entries();
    for lookalike in [
        "githubusercontent.com.attacker.example",
        "evilgithubusercontent.com",
        "notgithubusercontent.com",
    ] {
        let outcome = deny_check(lookalike, &entries);
        assert_eq!(
            outcome,
            proxy::ConnectionOutcome::Denied {
                host: Some(lookalike.to_string())
            }
        );
    }
}

/// A direct-IP-literal SNI (some TLS clients will send one if configured
/// to connect straight to an IP) matches no allowlist entry -- there is
/// no IP-based fallback path anywhere in the matcher or the proxy.
#[test]
fn a_direct_ip_literal_sni_is_denied() {
    let entries = egress_allowlist::default_entries();
    for ip_literal in ["93.184.216.34", "127.0.0.1", "0.0.0.0"] {
        let outcome = deny_check(ip_literal, &entries);
        assert_eq!(
            outcome,
            proxy::ConnectionOutcome::Denied {
                host: Some(ip_literal.to_string())
            }
        );
    }
}

/// A connection that supplies no SNI at all (the shape a raw direct-IP
/// TLS connection with no `server_name` extension would take, or a
/// non-TLS probe) is denied the same way a mismatched hostname is --
/// there is no "no SNI means allow it, we can't tell" fallback.
#[test]
fn a_connection_with_no_sni_extension_at_all_is_denied() {
    let entries = egress_allowlist::default_entries();
    let dialer = FakeDialer::default();
    let audit = MemoryAuditSink::default();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        // Raw bytes shaped like a plausible probe, never a valid
        // ClientHello with an SNI extension.
        connect_and_send(addr, &[0xffu8; 32]);
    });
    let (client, _) = listener.accept().unwrap();
    let outcome = proxy::handle_connection(client, &entries, &dialer, &audit).unwrap();
    assert_eq!(outcome, proxy::ConnectionOutcome::Denied { host: None });
    assert!(dialer.attempts.borrow().is_empty());
}

/// The nftables ruleset this crate builds must never contain a
/// blanket/any-destination accept rule -- the entire point of the
/// network-layer restriction is that the proxy is the *only* reachable
/// address, so a rule with no `daddr`/`dport` scoping, or a non-drop
/// default policy, would defeat it even if the SNI-matching logic above
/// is perfect.
#[test]
fn firewall_rules_never_contain_an_unscoped_accept() {
    let proxy_addr: SocketAddr = "10.0.2.100:8443".parse().unwrap();
    let rules = network_setup::build_egress_firewall_rules("pasta1", proxy_addr);

    assert!(
        rules.contains("policy drop"),
        "default policy must be drop, not accept -- fail closed on anything unmatched: {rules}"
    );
    for line in rules.lines().filter(|l| l.contains("accept")) {
        assert!(
            line.contains(&proxy_addr.ip().to_string())
                && line.contains(&proxy_addr.port().to_string()),
            "every accept rule must be scoped to the proxy's exact address and port: {line:?}"
        );
    }
}

/// The `podman run` network flags built for launch must never select
/// libkrun's default TSI mode (invisible to host firewall rules, the
/// entire reason `0004` moved to `passt`) or the host's own network
/// namespace -- the same "never widen host reach" invariant Phase 3's
/// `containment_escape.rs` pins for the container-privilege flags,
/// applied here to networking specifically.
#[test]
fn network_flags_never_select_host_networking_or_leave_it_unset() {
    let proxy_addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    let flags = network_setup::build_network_flags(proxy_addr);
    let joined = flags.join(" ");
    assert!(
        !joined.contains("host"),
        "must never use host networking: {flags:?}"
    );
    let net_idx = flags
        .iter()
        .position(|a| a == "--network")
        .expect("--network must be explicitly set");
    assert_eq!(flags[net_idx + 1], network_setup::NETWORK_MODE);
}
