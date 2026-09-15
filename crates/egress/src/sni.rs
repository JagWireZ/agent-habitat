//! Extracts the SNI (Server Name Indication) hostname from a raw TLS
//! ClientHello, without terminating or otherwise interpreting the TLS
//! session -- exactly the "destination inspection at connection setup,
//! not full TLS interception" the proxy is required to do
//! (`docs/decisions/0004-networking-layer.md`).
//!
//! Deliberately hand-rolled rather than pulling in a TLS crate: the only
//! thing this proxy needs from the ClientHello is the plaintext SNI
//! extension, which is sent unencrypted by design (that's precisely what
//! makes SNI-based filtering possible without terminating TLS) -- a full
//! TLS stack would be solving a much bigger problem than this one field.
//!
//! Parsing follows RFC 8446 (and RFC 5246 for the ClientHello framing,
//! unchanged across TLS 1.2/1.3 for this purpose) far enough to reach the
//! `server_name` extension (type `0x0000`) and its first `host_name`
//! entry. Anything short, truncated, or structurally unexpected returns
//! `None` -- callers treat `None` the same as "no allowlist entry
//! matched": deny the connection, never guess or fall back to some other
//! signal (`AGENTS.md` Section 2, invariant 7's fail-closed framing
//! applied here to parsing, not just policy lookup).

/// A byte-cursor helper so the parsing functions below stay linear and
/// bounds-checked without repeating `..` slicing arithmetic everywhere.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<u32> {
        self.take(3)
            .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
}

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const EXTENSION_TYPE_SERVER_NAME: u16 = 0x0000;
const SERVER_NAME_TYPE_HOST_NAME: u8 = 0x00;

/// Whether `buf` already holds a complete TLS record (its 5-byte header
/// plus the number of body bytes the header declares) -- used by the
/// proxy's read loop to know when to stop accumulating bytes before
/// attempting to parse, rather than parsing against a partially-read
/// buffer and misreading a truncated record as "no SNI present".
/// Returns `false` (never a panic or a guess) on anything shorter than
/// the header itself.
pub fn record_is_complete(buf: &[u8]) -> bool {
    if buf.len() < RECORD_HEADER_LEN {
        return false;
    }
    let body_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    buf.len() >= RECORD_HEADER_LEN + body_len
}

/// Extracts the SNI `host_name` from a single, complete TLS record
/// holding a ClientHello. `None` on anything not exactly that: wrong
/// content/handshake type, a truncated field, an absent `server_name`
/// extension, or an extension present but empty/malformed. Never panics
/// on attacker-controlled input -- every field read is bounds-checked
/// through `Cursor`.
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    let mut record = Cursor::new(buf);
    let content_type = record.u8()?;
    if content_type != CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    let _legacy_version = record.u16()?;
    let body_len = record.u16()? as usize;
    let body = record.take(body_len)?;

    let mut hs = Cursor::new(body);
    let hs_type = hs.u8()?;
    if hs_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }
    let hs_len = hs.u24()? as usize;
    let hello = hs.take(hs_len)?;

    let mut c = Cursor::new(hello);
    c.skip(2)?; // client_version
    c.skip(32)?; // random
    let session_id_len = c.u8()? as usize;
    c.skip(session_id_len)?;
    let cipher_suites_len = c.u16()? as usize;
    c.skip(cipher_suites_len)?;
    let compression_methods_len = c.u8()? as usize;
    c.skip(compression_methods_len)?;

    if c.remaining() == 0 {
        // No extensions block at all -- valid ClientHello shape, just no
        // SNI to find.
        return None;
    }
    let extensions_len = c.u16()? as usize;
    let extensions = c.take(extensions_len)?;

    find_server_name_extension(extensions)
}

fn find_server_name_extension(extensions: &[u8]) -> Option<String> {
    let mut c = Cursor::new(extensions);
    while c.remaining() >= 4 {
        let ext_type = c.u16()?;
        let ext_len = c.u16()? as usize;
        let ext_data = c.take(ext_len)?;
        if ext_type == EXTENSION_TYPE_SERVER_NAME {
            return parse_server_name_list(ext_data);
        }
    }
    None
}

fn parse_server_name_list(data: &[u8]) -> Option<String> {
    let mut c = Cursor::new(data);
    let _list_len = c.u16()?;
    // A ClientHello may in principle list more than one entry; TLS in
    // practice sends exactly one `host_name`, and that's the only entry
    // type this proxy acts on.
    while c.remaining() >= 3 {
        let name_type = c.u8()?;
        let name_len = c.u16()? as usize;
        let name = c.take(name_len)?;
        if name_type == SERVER_NAME_TYPE_HOST_NAME {
            return std::str::from_utf8(name).ok().map(str::to_string);
        }
    }
    None
}

pub mod testing {
    //! Builds a well-formed TLS 1.2/1.3-shaped ClientHello record
    //! carrying a given SNI hostname, byte-for-byte per RFC 8446, so
    //! tests exercise the real parser against real wire framing rather
    //! than a hand-simplified stand-in. Not `#[cfg(test)]`-gated -- like
    //! `habitat_vm::command_runner::testing`, this needs to be visible to
    //! external `[[test]]` targets (`tests/unit/egress/`,
    //! `tests/adversarial/egress_bypass.rs`), which compile against this
    //! crate as an ordinary dependency rather than in-crate `#[cfg(test)]`
    //! mode.

    pub fn build_client_hello(sni_host: &str) -> Vec<u8> {
        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // client_version: TLS 1.2
        hello_body.extend_from_slice(&[0u8; 32]); // random
        hello_body.push(0); // session_id_len
        hello_body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len
        hello_body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        hello_body.push(1); // compression_methods_len
        hello_body.push(0); // "null" compression

        let mut sni_ext = Vec::new();
        let mut name_entry = Vec::new();
        name_entry.push(0x00); // name_type: host_name
        name_entry.extend_from_slice(&(sni_host.len() as u16).to_be_bytes());
        name_entry.extend_from_slice(sni_host.as_bytes());
        sni_ext.extend_from_slice(&(name_entry.len() as u16).to_be_bytes()); // server_name_list len
        sni_ext.extend_from_slice(&name_entry);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // extension type: server_name
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let hs_len = hello_body.len() as u32;
        handshake.extend_from_slice(&hs_len.to_be_bytes()[1..]); // u24
        handshake.extend_from_slice(&hello_body);

        let mut record = Vec::new();
        record.push(0x16); // handshake content type
        record.extend_from_slice(&[0x03, 0x01]); // legacy record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::testing::build_client_hello;
    use super::*;

    #[test]
    fn extracts_sni_from_a_well_formed_client_hello() {
        let hello = build_client_hello("api.anthropic.com");
        assert!(record_is_complete(&hello));
        assert_eq!(extract_sni(&hello), Some("api.anthropic.com".to_string()));
    }

    #[test]
    fn returns_none_for_a_non_handshake_record() {
        let mut junk = vec![0x17, 0x03, 0x03]; // content type 0x17 = application_data
        junk.extend_from_slice(&[0x00, 0x05]);
        junk.extend_from_slice(b"hello");
        assert_eq!(extract_sni(&junk), None);
    }

    #[test]
    fn returns_none_for_garbage_bytes() {
        assert_eq!(extract_sni(b"not a tls record at all"), None);
        assert_eq!(extract_sni(b""), None);
    }

    #[test]
    fn returns_none_for_a_truncated_record_rather_than_panicking() {
        let hello = build_client_hello("example.com");
        for cut in [0, 1, 5, 10, hello.len() / 2] {
            // Must not panic on any prefix -- bounds-checked all the way
            // through, fails closed to `None` instead.
            assert_eq!(extract_sni(&hello[..cut]), None);
        }
    }

    #[test]
    fn record_is_complete_is_false_until_the_full_body_has_arrived() {
        let hello = build_client_hello("example.com");
        assert!(!record_is_complete(&hello[..RECORD_HEADER_LEN]));
        assert!(!record_is_complete(&hello[..hello.len() - 1]));
        assert!(record_is_complete(&hello));
    }

    #[test]
    fn returns_none_when_the_server_name_extension_is_absent() {
        // A structurally valid ClientHello with an empty extensions
        // block -- there's no SNI here to find, not a malformed one.
        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]);
        hello_body.extend_from_slice(&[0u8; 32]);
        hello_body.push(0);
        hello_body.extend_from_slice(&[0x00, 0x02]);
        hello_body.extend_from_slice(&[0x13, 0x01]);
        hello_body.push(1);
        hello_body.push(0);
        hello_body.extend_from_slice(&[0x00, 0x00]); // extensions_len = 0

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(hello_body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello_body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(extract_sni(&record), None);
    }
}
