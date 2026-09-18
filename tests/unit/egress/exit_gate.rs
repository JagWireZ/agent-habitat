//! Black-box tests of `habitat-egress`'s contract with the rest of the
//! system (checked-in config, `habitat-policy`) -- run through real
//! loopback sockets, not mocked TCP. The real exit gate -- a connection
//! trace confirming the `pasta`/nftables reachability restriction holds
//! from inside an actually-booted guest -- needs real KVM; see
//! `tests/manual/validate-egress.sh` instead.

use habitat_audit::MemoryAuditSink;
use habitat_egress::dialer::testing::FakeDialer;
use habitat_egress::sni::testing::build_client_hello;
use habitat_egress::{dns, network_setup, proxy};
use habitat_policy::{config, egress_allowlist};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn connect_and_send(addr: std::net::SocketAddr, bytes: &[u8]) -> TcpStream {
    let mut guest = TcpStream::connect(addr).unwrap();
    guest.write_all(bytes).unwrap();
    guest.shutdown(Shutdown::Write).unwrap();
    guest
}

/// A project's checked-in config addition to the egress allowlist actually
/// reaches the proxy's decision: the same hostname is denied before the
/// addition and allowed after, through the real config parser end to end.
#[test]
fn a_project_config_addition_actually_reaches_the_proxy_decision() {
    let base_entries = egress_allowlist::effective_entries(&[]);
    let audit = MemoryAuditSink::default();
    let dialer = FakeDialer::default();

    // Before the addition: denied.
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hello = build_client_hello("internal.registry.example");
        thread::spawn(move || {
            connect_and_send(addr, &hello);
        });
        let (client, _) = listener.accept().unwrap();
        let outcome = proxy::handle_connection(client, &base_entries, &dialer, &audit).unwrap();
        assert_eq!(
            outcome,
            proxy::ConnectionOutcome::Denied {
                host: Some("internal.registry.example".to_string())
            }
        );
    }

    // Parsed through the real config reader, not a struct literal.
    let parsed = config::parse("egress_allowlist_additions:\n  - internal.registry.example\n")
        .expect("valid config must parse");
    let effective_entries = egress_allowlist::effective_entries(&parsed.egress_allowlist_additions);

    let (upstream_listener, upstream_addr) = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    };
    let upstream_handle = thread::spawn(move || {
        let (mut conn, _) = upstream_listener.accept().unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).ok();
        buf
    });
    let dialer = FakeDialer::default().with_route("internal.registry.example", upstream_addr);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hello = build_client_hello("internal.registry.example");
    let hello_for_guest = hello.clone();
    thread::spawn(move || {
        connect_and_send(addr, &hello_for_guest);
    });
    let (client, _) = listener.accept().unwrap();
    let outcome = proxy::handle_connection(client, &effective_entries, &dialer, &audit).unwrap();
    assert_eq!(
        outcome,
        proxy::ConnectionOutcome::Allowed {
            host: "internal.registry.example".to_string()
        }
    );
    assert_eq!(upstream_handle.join().unwrap(), hello);

    // The default entries were never displaced by the project addition.
    assert!(effective_entries.contains(&"pypi.org".to_string()));
}

/// `dns_listen_addr` carries the proxy's real bound address, confirmed
/// against a real `TcpListener` rather than a hand-typed socket addr.
#[test]
fn network_flags_reflect_the_proxys_actual_bound_address() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let forwarder_addr = network_setup::dns_listen_addr(proxy_addr);
    assert_eq!(forwarder_addr.ip(), proxy_addr.ip());
}

/// DNS pinning forwards a real query end to end: guest socket -> forwarder
/// -> fixture upstream -> back to the guest, unmodified.
#[test]
fn dns_forwarder_relays_a_real_query_round_trip() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        if let Ok((n, src)) = upstream.recv_from(&mut buf) {
            let _ = upstream.send_to(&buf[..n], src);
        }
    });

    let forwarder_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let forwarder_addr = forwarder_socket.local_addr().unwrap();
    drop(forwarder_socket);

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);
    let upstream_str = upstream_addr.to_string();
    let handle = thread::spawn(move || dns::run(forwarder_addr, &upstream_str, running_clone));
    thread::sleep(Duration::from_millis(50));

    let guest = UdpSocket::bind("127.0.0.1:0").unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    guest.send_to(b"a-dns-query", forwarder_addr).unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = guest.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"a-dns-query");

    running.store(false, Ordering::SeqCst);
    handle.join().unwrap().unwrap();
}
