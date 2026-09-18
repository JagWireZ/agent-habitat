//! Session identity and the request/handle types the launcher and
//! teardown logic operate on.

use habitat_policy::resource_limits::ResourceLimitsConfig;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Uniquely identifies one session. Used directly as the podman container
/// name, so it must satisfy podman's name syntax
/// (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Generates a fresh id: a fixed prefix plus a timestamp and a
    /// disambiguating suffix. No external RNG needed -- `process::id()`
    /// XORed with low bits of a nanosecond timestamp is enough to avoid
    /// collisions in practice.
    pub fn generate() -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let suffix = (std::process::id() as u128) ^ (ts & 0xffff_ffff);
        SessionId(format!("habitat-{ts:x}-{suffix:x}"))
    }

    /// Builds a `SessionId` from an already-known name, rejecting
    /// anything that isn't a valid podman container name.
    pub fn from_name(name: impl Into<String>) -> Result<Self, String> {
        let name = name.into();
        let starts_ok = name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false);
        let body_ok = name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        if starts_ok && body_ok {
            Ok(SessionId(name))
        } else {
            Err(format!("{name:?} is not a valid podman container name"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Everything needed to launch one session's microVM.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub session_id: SessionId,
    /// Disk image to attach as the guest's extra `virtio-blk` workspace
    /// device -- never the guest's root filesystem itself.
    pub workspace_disk_path: PathBuf,
    /// Guest OS container image reference -- a fixed Alpine image, never
    /// chosen independently per project or session.
    pub guest_image: String,
    pub resource_limits: ResourceLimitsConfig,
    /// The local egress proxy's bound address for this session -- the
    /// guest's network is configured so this is the *only* address it
    /// can reach. Required: there is no launch path with no egress proxy.
    pub egress_proxy_addr: SocketAddr,
    /// This session's ephemeral SSH public key
    /// (`guest_ssh::SessionKeypair::public_key`), baked into the guest
    /// via env var at launch since `podman exec` doesn't work against
    /// `krun`. Not a secret; the private key stays host-side.
    pub guest_ssh_public_key: String,
    /// Where the private half of `guest_ssh_public_key`'s keypair lives
    /// on the host, carried through so `launch` can copy it onto the
    /// returned `LaunchedSession` for `teardown` to clean up.
    pub guest_ssh_private_key_path: PathBuf,
}

/// What a successful launch hands back -- enough to tear the session
/// down later, nothing more.
#[derive(Debug, Clone)]
pub struct LaunchedSession {
    pub session_id: SessionId,
    pub workspace_disk_path: PathBuf,
    /// Host address the guest's `sshd` port was published to -- always
    /// `launcher::GUEST_SSH_HOST` (loopback).
    pub guest_ssh_host: String,
    /// Host port the guest's `sshd` was published to, resolved by
    /// `launcher::guest_ssh_port` after a successful launch (`pasta`
    /// gives no separate, `podman inspect`-visible guest IP to use
    /// instead).
    pub guest_ssh_port: u16,
    /// Where this session's ephemeral private SSH key lives on the host,
    /// so `teardown` can delete it alongside the disk image.
    pub guest_ssh_private_key_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_valid_podman_names_and_unique() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert!(SessionId::from_name(a.as_str().to_string()).is_ok());
        assert!(SessionId::from_name(b.as_str().to_string()).is_ok());
        assert_ne!(a, b, "two ids generated back to back must not collide");
        assert!(a.as_str().starts_with("habitat-"));
    }

    #[test]
    fn from_name_accepts_valid_podman_names() {
        assert!(SessionId::from_name("habitat-1a2b-3c4d").is_ok());
        assert!(SessionId::from_name("session.1_2-3").is_ok());
    }

    #[test]
    fn from_name_rejects_invalid_podman_names() {
        assert!(SessionId::from_name("-leading-dash").is_err());
        assert!(SessionId::from_name("has space").is_err());
        assert!(SessionId::from_name("has/slash").is_err());
        assert!(SessionId::from_name("").is_err());
    }
}
