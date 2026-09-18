//! The local proxy: the single point every guest connection must pass
//! through, enforcing the default-deny, SNI-based allowlist
//! (`docs/decisions/0004-networking-layer.md`). Making this proxy the
//! *only* reachable address is `crate::network_setup`'s job.
//!
//! One connection, one decision made once: read the ClientHello, extract
//! its SNI hostname ([`crate::sni`]), check it against the allowlist
//! ([`habitat_policy::egress_allowlist`]), and either relay raw bytes to
//! the real destination on port 443 (no TLS termination) or close
//! immediately. Nothing is written to the destination until the decision
//! is `Allowed`.

use crate::dialer::Dialer;
use crate::sni;
use habitat_audit::{AuditEvent, AuditSink, EventKind};
use habitat_policy::egress_allowlist;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

/// Every allowed connection is forwarded here; every allowlist entry is an
/// HTTPS API or package registry (`policy/egress_allowlist.txt`).
pub const UPSTREAM_TLS_PORT: u16 = 443;

/// Buffer cap while waiting for a complete TLS record: TLS's max record
/// body (2^14) plus the 5-byte header, so no well-formed ClientHello is
/// cut off while a flooding connection is still bounded.
const MAX_HELLO_BYTES: usize = 5 + 16384;

/// One connection's outcome, so tests can observe it without re-deriving
/// it from log side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionOutcome {
    /// Relayed to `host` until either side closed the connection.
    Allowed { host: String },
    /// Closed without ever dialing out. `host` is `None` when no SNI
    /// could be read at all (missing extension, malformed record, or
    /// too little data arrived before the guest gave up).
    Denied { host: Option<String> },
}

/// Reads until a complete TLS record is buffered, then makes and acts on
/// the allow/deny decision. Fails closed at every step.
pub fn handle_connection<D: Dialer, A: AuditSink>(
    mut client: TcpStream,
    allowlist: &[String],
    dialer: &D,
    audit: &A,
) -> io::Result<ConnectionOutcome> {
    let hello = match read_client_hello(&mut client)? {
        Some(bytes) => bytes,
        None => {
            emit(audit, EventKind::EgressDenied, None);
            return Ok(ConnectionOutcome::Denied { host: None });
        }
    };

    let host = sni::extract_sni(&hello);
    let host = match host {
        Some(h) => h,
        None => {
            emit(audit, EventKind::EgressDenied, None);
            return Ok(ConnectionOutcome::Denied { host: None });
        }
    };

    if !egress_allowlist::is_allowed(allowlist, &host) {
        emit(audit, EventKind::EgressDenied, Some(&host));
        return Ok(ConnectionOutcome::Denied { host: Some(host) });
    }

    emit(audit, EventKind::EgressAllowed, Some(&host));
    let mut upstream = dialer.connect(&host, UPSTREAM_TLS_PORT)?;
    upstream.write_all(&hello)?;
    relay(client, upstream)?;
    Ok(ConnectionOutcome::Allowed { host })
}

/// Accumulates bytes until [`sni::record_is_complete`] says a full record
/// has arrived. `Ok(None)` (not an error) on a clean EOF before that.
fn read_client_hello(client: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = client.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if sni::record_is_complete(&buf) {
            return Ok(Some(buf));
        }
        if buf.len() >= MAX_HELLO_BYTES {
            return Ok(None);
        }
    }
}

/// Bidirectionally copies bytes between `client` and `upstream` until
/// either side closes.
fn relay(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream;

    let to_upstream = thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(std::net::Shutdown::Write);
    });
    let to_client = thread::spawn(move || {
        let _ = io::copy(&mut upstream_read, &mut client_write);
        let _ = client_write.shutdown(std::net::Shutdown::Write);
    });
    let _ = to_upstream.join();
    let _ = to_client.join();
    Ok(())
}

fn emit<A: AuditSink>(audit: &A, kind: EventKind, host: Option<&str>) {
    let message = match host {
        Some(h) => format!("egress connection for {h}"),
        None => "egress connection with no readable SNI hostname".to_string(),
    };
    let _ = audit.record(&AuditEvent::now(kind, host, message));
}

/// Runs the proxy's accept loop until the listener errors out. Each
/// connection is handled on its own thread.
pub fn run<D, A>(
    listen_addr: std::net::SocketAddr,
    allowlist: Vec<String>,
    dialer: Arc<D>,
    audit: Arc<A>,
) -> io::Result<()>
where
    D: Dialer + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
{
    let listener = TcpListener::bind(listen_addr)?;
    for stream in listener.incoming() {
        let stream = stream?;
        let allowlist = allowlist.clone();
        let dialer = Arc::clone(&dialer);
        let audit = Arc::clone(&audit);
        thread::spawn(move || {
            let _ = handle_connection(stream, &allowlist, &*dialer, &*audit);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::testing::FakeDialer;
    use crate::sni::testing::build_client_hello;
    use habitat_audit::MemoryAuditSink;
    use std::net::{Shutdown, TcpListener};

    /// Fixture "real destination": accepts one connection, records what it
    /// received, writes back a fixed response, then closes.
    fn spawn_fixture_upstream_with_response(
        response: &'static [u8],
    ) -> (std::net::SocketAddr, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            conn.read_to_end(&mut received).unwrap_or(0);
            let _ = conn.write_all(response);
            let _ = conn.shutdown(Shutdown::Write);
            received
        });
        (addr, handle)
    }

    fn connect_guest_and_send(proxy_addr: std::net::SocketAddr, bytes: &[u8]) -> TcpStream {
        let mut guest = TcpStream::connect(proxy_addr).unwrap();
        guest.write_all(bytes).unwrap();
        guest.shutdown(Shutdown::Write).unwrap();
        guest
    }

    #[test]
    fn an_allowlisted_destination_is_relayed_end_to_end() {
        let (upstream_addr, upstream_handle) =
            spawn_fixture_upstream_with_response(b"pretend-tls-server-response");
        let dialer = FakeDialer::default().with_route("api.anthropic.com", upstream_addr);
        let audit = MemoryAuditSink::default();
        let allowlist = vec!["api.anthropic.com".to_string()];

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let hello = build_client_hello("api.anthropic.com");

        let guest_handle = {
            let hello = hello.clone();
            thread::spawn(move || {
                let mut guest = connect_guest_and_send(proxy_addr, &hello);
                let mut response = Vec::new();
                guest.read_to_end(&mut response).unwrap();
                response
            })
        };

        let (client, _) = proxy_listener.accept().unwrap();
        let outcome = handle_connection(client, &allowlist, &dialer, &audit).unwrap();

        assert_eq!(
            outcome,
            ConnectionOutcome::Allowed {
                host: "api.anthropic.com".to_string()
            }
        );
        let received_by_upstream = upstream_handle.join().unwrap();
        assert_eq!(
            received_by_upstream, hello,
            "upstream must see the exact ClientHello bytes"
        );
        let response_seen_by_guest = guest_handle.join().unwrap();
        assert_eq!(response_seen_by_guest, b"pretend-tls-server-response");

        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::EgressAllowed);
        assert_eq!(events[0].check.as_deref(), Some("api.anthropic.com"));
    }

    #[test]
    fn a_non_allowlisted_destination_is_denied_without_ever_dialing_out() {
        let dialer = FakeDialer::default(); // no routes configured at all
        let audit = MemoryAuditSink::default();
        let allowlist = vec!["api.anthropic.com".to_string()];

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let hello = build_client_hello("attacker.example");

        let guest_handle = thread::spawn(move || {
            let mut guest = connect_guest_and_send(proxy_addr, &hello);
            let mut response = Vec::new();
            guest.read_to_end(&mut response).unwrap();
            response
        });

        let (client, _) = proxy_listener.accept().unwrap();
        let outcome = handle_connection(client, &allowlist, &dialer, &audit).unwrap();

        assert_eq!(
            outcome,
            ConnectionOutcome::Denied {
                host: Some("attacker.example".to_string())
            }
        );
        assert!(
            dialer.attempts.borrow().is_empty(),
            "a denied hostname must never trigger an outbound dial"
        );
        let response_seen_by_guest = guest_handle.join().unwrap();
        assert!(
            response_seen_by_guest.is_empty(),
            "a denied guest must see the connection closed, not any relayed bytes"
        );

        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::EgressDenied);
        assert_eq!(events[0].check.as_deref(), Some("attacker.example"));
    }

    /// A crafted allowlist-lookalike hostname (e.g. smuggling past
    /// `*.example.com` with `example.com.attacker.example`) must be denied
    /// like any other non-match.
    #[test]
    fn an_allowlist_lookalike_hostname_is_denied() {
        let dialer = FakeDialer::default();
        let audit = MemoryAuditSink::default();
        let allowlist = vec!["*.githubusercontent.com".to_string()];

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let hello = build_client_hello("githubusercontent.com.attacker.example");

        thread::spawn(move || {
            connect_guest_and_send(proxy_addr, &hello);
        });

        let (client, _) = proxy_listener.accept().unwrap();
        let outcome = handle_connection(client, &allowlist, &dialer, &audit).unwrap();
        assert_eq!(
            outcome,
            ConnectionOutcome::Denied {
                host: Some("githubusercontent.com.attacker.example".to_string())
            }
        );
        assert!(dialer.attempts.borrow().is_empty());
    }

    /// A direct-IP connection carries no SNI hostname; the proxy has no
    /// IP-based fallback, so this must be denied like any other.
    #[test]
    fn a_connection_with_no_readable_sni_is_denied() {
        let dialer = FakeDialer::default();
        let audit = MemoryAuditSink::default();
        let allowlist = vec!["api.anthropic.com".to_string()];

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        thread::spawn(move || {
            connect_guest_and_send(proxy_addr, b"GET / HTTP/1.1\r\nHost: evil\r\n\r\n");
        });

        let (client, _) = proxy_listener.accept().unwrap();
        let outcome = handle_connection(client, &allowlist, &dialer, &audit).unwrap();
        assert_eq!(outcome, ConnectionOutcome::Denied { host: None });
        assert!(dialer.attempts.borrow().is_empty());

        let events = audit.events.lock().unwrap();
        assert_eq!(events[0].kind, EventKind::EgressDenied);
        assert_eq!(events[0].check, None);
    }

    #[test]
    fn a_guest_that_disconnects_before_sending_a_full_hello_is_denied_not_errored() {
        let dialer = FakeDialer::default();
        let audit = MemoryAuditSink::default();
        let allowlist = vec!["api.anthropic.com".to_string()];

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        thread::spawn(move || {
            connect_guest_and_send(proxy_addr, &[0x16, 0x03, 0x01]);
        });

        let (client, _) = proxy_listener.accept().unwrap();
        let outcome = handle_connection(client, &allowlist, &dialer, &audit).unwrap();
        assert_eq!(outcome, ConnectionOutcome::Denied { host: None });
        assert!(dialer.attempts.borrow().is_empty());
    }
}
