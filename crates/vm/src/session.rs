//! Session identity and the request/handle types the launcher and
//! teardown logic operate on.

use habitat_policy::resource_limits::ResourceLimitsConfig;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Uniquely identifies one session. Used directly as the podman container
/// name, so it must satisfy podman's name syntax
/// (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`) -- and, from Phase 6 on, as the tag
/// audit-log events for this session attach to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Generates a fresh id: a fixed prefix (recognizable at a glance in
    /// `podman ps` output, next to whatever else a host happens to be
    /// running) plus a timestamp and a disambiguating suffix. No external
    /// RNG dependency is taken for that suffix -- `std::process::id()`
    /// XORed with the low bits of a nanosecond timestamp is enough to
    /// keep two ids generated in the same process, or in two processes
    /// started in the same nanosecond, from colliding in practice.
    pub fn generate() -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let suffix = (std::process::id() as u128) ^ (ts & 0xffff_ffff);
        SessionId(format!("habitat-{ts:x}-{suffix:x}"))
    }

    /// Builds a `SessionId` from an already-known name (e.g. read back
    /// from `podman ps` during a later phase's session-recovery logic) --
    /// rejects anything that isn't a valid podman container name rather
    /// than silently accepting it.
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
    /// The Phase 2 disk image to attach as the guest's extra
    /// `virtio-blk` workspace device (`0005-storage-layer.md`) -- never
    /// the guest's root filesystem itself.
    pub workspace_disk_path: PathBuf,
    /// The guest OS container image reference (`0002-guest-os-layer.md`)
    /// -- a fixed Alpine image, independent of the host roadmap stage
    /// (never AlmaLinux/Fedora/Ubuntu, and never chosen independently
    /// per project or per session).
    pub guest_image: String,
    pub resource_limits: ResourceLimitsConfig,
    /// The local egress proxy's bound address for this session
    /// (`habitat_egress::proxy`) -- the guest's network is configured
    /// (Phase 5, `habitat_egress::network_setup`) so this is the *only*
    /// address it can reach at all. Required, not optional: there is no
    /// launch path with no egress proxy configured (`AGENTS.md` Section
    /// 2, invariant 7 -- fail closed on missing egress control, never
    /// open by default).
    pub egress_proxy_addr: SocketAddr,
    /// This session's ephemeral SSH public key content
    /// (`habitat_vm::guest_ssh::SessionKeypair::public_key`), baked into
    /// the guest via an environment variable at launch
    /// (`docs/decisions/0008-guest-exec-channel.md`) since `podman exec`
    /// does not work against the `krun` runtime at all. Not a secret --
    /// the corresponding private key stays host-side and is never part
    /// of this request.
    pub guest_ssh_public_key: String,
    /// Where the private half of `guest_ssh_public_key`'s keypair lives
    /// on the host (`habitat_vm::guest_ssh::generate`) -- carried through
    /// so `launch` can copy it onto the returned `LaunchedSession` for
    /// `teardown` to clean up. This request never needs to *read* the
    /// private key itself, only remember where it is.
    pub guest_ssh_private_key_path: PathBuf,
}

/// What a successful launch hands back -- enough to tear the session
/// down later, nothing more. No live handle/mount is kept open beyond
/// this (`AGENTS.md` Section 2, invariant 1).
#[derive(Debug, Clone)]
pub struct LaunchedSession {
    pub session_id: SessionId,
    pub workspace_disk_path: PathBuf,
    /// Host address the guest's `sshd` port was published to
    /// (`docs/decisions/0008-guest-exec-channel.md`) -- always
    /// `launcher::GUEST_SSH_HOST` (loopback), never a value that could
    /// make this exec channel reachable from outside the host machine.
    pub guest_ssh_host: String,
    /// Host port the guest's `sshd` was published to. Resolved by
    /// `launcher::guest_ssh_port` after a successful launch --
    /// confirmed on real hardware that `pasta` gives no separate,
    /// `podman inspect`-visible guest IP to address directly (an earlier
    /// version of this field was a guest IP address for exactly that
    /// reason, before real-hardware testing showed `NetworkSettings`
    /// comes back empty for a `pasta`-backed container).
    pub guest_ssh_port: u16,
    /// Where this session's ephemeral private SSH key lives on the host
    /// (`habitat_vm::guest_ssh`) -- carried here so `teardown` can delete
    /// it alongside the disk image, never leaving a session's credential
    /// behind after the session it authorized is gone.
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
