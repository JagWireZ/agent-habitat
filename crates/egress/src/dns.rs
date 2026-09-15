//! Pins guest DNS resolution to the proxy path (`docs/decisions/
//! 0004-networking-layer.md`'s open item): the guest's only reachable
//! address is this proxy (`crate::network_setup` restricts everything
//! else at the network layer), so its resolver must be pointed here too
//! -- otherwise a leftover default DNS server the guest never actually
//! *asks the proxy about* would be a way for the reachability
//! restriction to quietly leak (the guest could still resolve names, or
//! be handed poisoned answers, over a path the SNI proxy never sees).
//!
//! This module does not filter *which* names may be resolved -- doing
//! that would be redundant with, and weaker than, the real gate: the
//! proxy already denies by destination hostname at connection setup
//! (`crate::proxy`), so restricting resolution itself would only add a
//! second, IP-flavored check of the exact kind `0004` deliberately
//! avoids. It only forwards each query to a fixed upstream resolver and
//! returns the answer verbatim -- resolution keeps working normally,
//! and it stays on the one path this proxy can see.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A public resolver used as the fixed upstream in the absence of any
/// project-specific override -- Phase 7's config file is expected to add
/// an override field here the same way it extends every other Phase 2-5
/// built-in default, not to replace this constant's role as the
/// built-in fallback.
pub const DEFAULT_UPSTREAM_DNS: &str = "1.1.1.1:53";

/// How long a single forwarded query waits for the upstream resolver to
/// answer before giving up. A denial-by-timeout is the fail-closed
/// outcome here too: no answer is sent back to the guest rather than
/// blocking the forwarder loop indefinitely on one slow or absent
/// upstream.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Forwards one raw DNS query datagram to `upstream` and returns its raw
/// response datagram, unmodified. Uses a fresh ephemeral local socket per
/// call rather than reusing the forwarder's own listening socket, so a
/// slow upstream on one query can never block the receipt of another.
pub fn forward_query(query: &[u8], upstream: &str) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    socket.connect(upstream)?;
    socket.send(query)?;
    let mut buf = [0u8; 4096];
    let n = socket.recv(&mut buf)?;
    Ok(buf[..n].to_vec())
}

/// Runs the forwarder's receive loop against `listen_addr` (the address
/// the guest's resolver is pointed at) until `running` is cleared. Each
/// query is forwarded and answered synchronously; on any forwarding
/// failure (upstream unreachable, timed out, or a malformed response),
/// no reply is sent to the guest at all -- fail closed on a broken
/// upstream rather than fabricate or repeat a stale answer.
pub fn run(listen_addr: SocketAddr, upstream: &str, running: Arc<AtomicBool>) -> io::Result<()> {
    let socket = UdpSocket::bind(listen_addr)?;
    // Bounded so the loop notices `running` being cleared promptly
    // instead of blocking on `recv_from` forever with nothing arriving.
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut buf = [0u8; 4096];
    while running.load(Ordering::SeqCst) {
        let (n, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        if let Ok(response) = forward_query(&buf[..n], upstream) {
            let _ = socket.send_to(&response, src);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// A minimal fixture "upstream resolver": answers every query with a
    /// fixed, recognizable response so the test can confirm the
    /// forwarder relayed the query and returned the exact answer, not
    /// some transformation of it.
    fn spawn_fixture_upstream() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, src)) = socket.recv_from(&mut buf) {
                assert_eq!(&buf[..n], b"pretend-dns-query");
                let _ = socket.send_to(b"pretend-dns-answer", src);
            }
        });
        addr
    }

    #[test]
    fn forward_query_relays_to_upstream_and_returns_its_answer_verbatim() {
        let upstream = spawn_fixture_upstream();
        let response = forward_query(b"pretend-dns-query", &upstream.to_string()).unwrap();
        assert_eq!(response, b"pretend-dns-answer");
    }

    #[test]
    fn forward_query_fails_closed_when_upstream_is_unreachable() {
        // Port 1 on loopback: nothing is listening there.
        let result = forward_query(b"pretend-dns-query", "127.0.0.1:1");
        assert!(
            result.is_err(),
            "an unreachable upstream must be an error, never a fabricated answer"
        );
    }

    #[test]
    fn run_forwards_a_query_from_a_guest_socket_and_stops_when_asked() {
        let upstream = spawn_fixture_upstream();
        let listener_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener_socket.local_addr().unwrap();
        drop(listener_socket); // free the port for `run` to bind

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);
        let upstream_str = upstream.to_string();
        let server = thread::spawn(move || run(listen_addr, &upstream_str, running_clone));

        // Give the forwarder a moment to bind before the guest queries it.
        thread::sleep(Duration::from_millis(50));

        let guest = UdpSocket::bind("127.0.0.1:0").unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        guest.send_to(b"pretend-dns-query", listen_addr).unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = guest.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"pretend-dns-answer");

        running.store(false, Ordering::SeqCst);
        server.join().unwrap().unwrap();
    }
}
