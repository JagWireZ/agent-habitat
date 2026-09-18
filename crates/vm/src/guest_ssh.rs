//! Per-session ephemeral SSH keypair generation -- the credential that
//! authorizes this host to reach a session's guest over the exec channel
//! (`docs/decisions/0008-guest-exec-channel.md`), since `podman exec`
//! does not work against the `krun` runtime at all.
//!
//! A fresh keypair every session: the private key never leaves the host
//! and is deleted at teardown (`crate::launcher::teardown`). The public
//! key is not a secret, so baking it into the guest as a plaintext env
//! var (`crate::launcher::AUTHORIZED_KEY_ENV`) is fine.

use crate::command_runner::CommandRunner;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestSshKeyError {
    pub message: String,
}

impl fmt::Display for GuestSshKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "guest ssh key: {}", self.message)
    }
}

impl std::error::Error for GuestSshKeyError {}

fn err(message: impl Into<String>) -> GuestSshKeyError {
    GuestSshKeyError {
        message: message.into(),
    }
}

/// One session's generated keypair: where the private key lives on the
/// host, and the public key's content (safe to pass to the guest
/// verbatim).
#[derive(Debug, Clone)]
pub struct SessionKeypair {
    pub private_key_path: PathBuf,
    pub public_key: String,
}

fn public_key_path(private_key_path: &Path) -> PathBuf {
    let mut s = private_key_path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

/// Generates a fresh ed25519 keypair at `private_key_path` (and sibling
/// `<private_key_path>.pub`), with no passphrase -- there's no operator
/// present to answer an interactive prompt. Fails closed on any
/// `ssh-keygen` error.
pub fn generate<R: CommandRunner>(
    private_key_path: &Path,
    runner: &R,
) -> Result<SessionKeypair, GuestSshKeyError> {
    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| err(format!("could not create {}: {e}", parent.display())))?;
    }
    let path_str = private_key_path
        .to_str()
        .ok_or_else(|| err("private key path is not valid UTF-8"))?;

    let output = runner
        .run(
            "ssh-keygen",
            &[
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                path_str,
                "-C",
                "habitat-session",
                "-q",
            ],
        )
        .map_err(|e| {
            err(format!(
                "could not run `ssh-keygen` (is openssh-keygen/openssh-clients installed?): {e}"
            ))
        })?;
    if !output.status.success() {
        return Err(err(format!(
            "`ssh-keygen` exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let pub_path = public_key_path(private_key_path);
    let public_key = std::fs::read_to_string(&pub_path)
        .map_err(|e| {
            err(format!(
                "could not read generated public key {}: {e}",
                pub_path.display()
            ))
        })?
        .trim()
        .to_string();

    Ok(SessionKeypair {
        private_key_path: private_key_path.to_path_buf(),
        public_key,
    })
}

/// Removes both halves of a session's keypair. Idempotent -- a
/// missing/already-removed key is not an error.
pub fn cleanup(private_key_path: &Path) -> std::io::Result<()> {
    for path in [
        private_key_path.to_path_buf(),
        public_key_path(private_key_path),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::testing::FakeCommandRunner;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "habitat-guest-ssh-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn generate_fails_closed_when_ssh_keygen_is_not_on_path() {
        let path = temp_path("no-keygen");
        let runner = FakeCommandRunner::default(); // nothing configured
        let result = generate(&path, &runner);
        assert!(result.is_err());
    }

    #[test]
    fn generate_fails_closed_when_ssh_keygen_exits_non_zero() {
        let path = temp_path("keygen-fails");
        let path_str = path.to_str().unwrap().to_string();
        let invocation = format!("ssh-keygen -t ed25519 -N  -f {path_str} -C habitat-session -q");
        let runner = FakeCommandRunner::default().with_failure(&invocation, "boom");
        let result = generate(&path, &runner);
        assert!(result.is_err());
    }

    #[test]
    fn cleanup_is_idempotent_when_nothing_was_ever_generated() {
        let path = temp_path("never-generated");
        assert!(cleanup(&path).is_ok());
        assert!(cleanup(&path).is_ok());
    }

    #[test]
    fn cleanup_removes_both_private_and_public_key_files() {
        let path = temp_path("real-files");
        std::fs::write(&path, b"pretend private key").unwrap();
        std::fs::write(public_key_path(&path), b"pretend public key").unwrap();

        cleanup(&path).unwrap();

        assert!(!path.exists());
        assert!(!public_key_path(&path).exists());
    }
}
