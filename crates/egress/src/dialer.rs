//! Seam between the proxy's connection-handling logic and the outbound TCP
//! connection it opens, so allow/deny/relay logic is unit-testable over
//! real loopback sockets without a real destination host on the network.

use std::io;
use std::net::TcpStream;

/// Opens an outbound TCP connection to `host:port`. Returns `Err` if the
/// connection could not be established at all -- the proxy propagates
/// that as a failed relay, never a silent "pretend it worked".
pub trait Dialer {
    fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream>;
}

/// The real, unmocked dialer -- resolves `host` via the ordinary system
/// resolver and connects on `port`.
pub struct SystemDialer;

impl Dialer for SystemDialer {
    fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        TcpStream::connect((host, port))
    }
}

pub mod testing {
    //! An in-memory `Dialer` for tests: maps an allowed hostname to a
    //! real loopback address (e.g. a fixture "upstream" `TcpListener`)
    //! instead of resolving it for real, and records every dial attempt
    //! so a test can assert a denied connection never triggers one.

    use super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;

    #[derive(Default)]
    pub struct FakeDialer {
        routes: HashMap<String, SocketAddr>,
        /// Every `(host, port)` pair actually dialed, in order -- a
        /// denied connection must never add an entry here.
        pub attempts: std::cell::RefCell<Vec<(String, u16)>>,
    }

    impl FakeDialer {
        pub fn with_route(mut self, host: &str, redirect_to: SocketAddr) -> Self {
            self.routes.insert(host.to_string(), redirect_to);
            self
        }
    }

    impl Dialer for FakeDialer {
        fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
            self.attempts.borrow_mut().push((host.to_string(), port));
            match self.routes.get(host) {
                Some(addr) => TcpStream::connect(addr),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("fake: no route configured for {host}:{port}"),
                )),
            }
        }
    }
}
