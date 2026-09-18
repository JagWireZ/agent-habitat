//! Pins guest DNS resolution to the proxy path (`docs/decisions/
//! 0004-networking-layer.md`): a leftover default DNS server the guest
//! never asks the proxy about would let the reachability restriction leak.
//!
//! Deliberately doesn't filter *which* names may be resolved — that would
//! duplicate the real gate (`crate::proxy` denies by destination hostname
//! at connection setup). It only forwards each query to a fixed upstream
//! and returns the answer verbatim.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Public resolver used as the fixed upstream absent a project-specific
/// override.
pub const DEFAULT_UPSTREAM_DNS: &str = "1.1.1.1:53";

/// How long a forwarded query waits for the upstream to answer before
/// giving up; times out fail-closed, no answer sent to the guest.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Forwards one raw DNS query datagram to `upstream` and returns its
/// response unmodified. Uses a fresh ephemeral socket per call so a slow
/// upstream on one query can't block another.
pub fn forward_query(query: &[u8], upstream: &str) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    socket.connect(upstream)?;
    socket.send(query)?;
    let mut buf = [0u8; 4096];
    let n = socket.recv(&mut buf)?;
    Ok(buf[..n].to_vec())
}

/// Runs the forwarder's receive loop against `listen_addr` until `running`
/// is cleared. Any forwarding failure means no reply is sent — fail closed
/// rather than fabricate or repeat a stale answer.
pub fn run(listen_addr: SocketAddr, upstream: &str, running: Arc<AtomicBool>) -> io::Result<()> {
    let socket = UdpSocket::bind(listen_addr)?;
    // Bounded so the loop notices `running` clearing promptly instead of
    // blocking on `recv_from` forever.
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

    /// Fixture "upstream resolver": answers every query with a fixed,
    /// recognizable response.
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
