//! The seam between this crate's sync logic and an actual running guest
//! session: every guest-side operation goes through the real `ssh`/`scp`
//! binaries against the guest's published SSH port and this session's
//! ephemeral private key (`habitat_vm::guest_ssh`), through whatever
//! `CommandRunner` the caller supplies -- mirroring `habitat-vm`'s own
//! `CommandRunner` seam for the launcher rather than introducing a
//! second shelling-out mechanism.
//!
//! **This was `podman exec`/`podman cp` through Phase 4's first
//! implementation.** A real run against a real, booted `krun` guest
//! confirmed that does not work at all -- `podman exec` is unconditionally
//! unsupported against the `krun` runtime (`the handler does not support
//! exec`), a real, currently-unresolved upstream limitation, not
//! something specific to this project's setup. A *second* real run then
//! confirmed the initial SSH-by-guest-IP fix's own assumption was also
//! wrong: `pasta` gives no separate, `podman inspect`-visible guest IP to
//! dial -- reachability is by an explicitly published port on
//! `127.0.0.1` instead (`habitat_vm::launcher::guest_ssh_port`). See
//! `docs/decisions/0008-guest-exec-channel.md` for the full story.
//! `crate::sync`'s call sites (`.exec()`, `.exec_with_env()`,
//! `.copy_in()`) are unchanged by either correction -- only what happens
//! inside this module changed.
//!
//! Actually exercising this against a real, booted guest needs real KVM
//! (`habitat-vm`'s own exit gate) -- so, same as before, the pure
//! argv-construction logic here is fully unit-tested against a
//! `FakeCommandRunner`; the real, booted round-trip is
//! `tests/manual/validate-sync.sh`'s job.

use crate::command_runner::CommandRunner;
use std::io;
use std::path::Path;
use std::process::Output;

/// The guest-side account every session's `sshd` accepts connections for
/// (`guest/Containerfile`) -- a single, dedicated, unprivileged user,
/// never `root`.
pub const GUEST_SSH_USER: &str = "habitat";

/// Everything needed to reach one session's guest over SSH: the host
/// address/port its `sshd` was published to (`habitat_vm::launcher`'s
/// `GUEST_SSH_HOST`/`guest_ssh_port` -- always loopback, see that
/// module's real-hardware caveat on why there's no separate guest IP to
/// address directly under `pasta`) and the per-session ephemeral private
/// key (`habitat_vm::guest_ssh::generate`) authorized for it.
#[derive(Debug, Clone, Copy)]
pub struct GuestEndpoint<'a> {
    pub host: &'a str,
    pub port: u16,
    pub private_key_path: &'a Path,
}

/// Runs commands *inside* one running guest session via `ssh`, and
/// copies a file in via `scp`, through whatever `CommandRunner` the
/// caller supplies for the actual invocation -- this struct never shells
/// out on its own, it only builds the right argv and delegates.
pub struct GuestExecRunner<'a, R: CommandRunner> {
    inner: &'a R,
    endpoint: GuestEndpoint<'a>,
}

/// Common `-i`/`-o` options shared by both `ssh` and `scp` invocations --
/// exposed (not private) so external test targets (`tests/unit/workspace/`,
/// `tests/adversarial/`) can build the exact expected invocation string
/// for a `FakeCommandRunner` mock without hand-duplicating this flag
/// list, the same reason `shell_quote` is public.
///
/// - `IdentitiesOnly=yes` -- use exactly the session key given, never any
///   other identity the calling user's own `ssh-agent` or `~/.ssh/config`
///   might otherwise offer.
/// - `StrictHostKeyChecking=accept-new` with `UserKnownHostsFile=/dev/null`
///   -- this session's guest is a brand-new host every time (a fresh
///   microVM, not a long-lived server), so there is no persistent host
///   identity worth pinning across sessions; accept-on-first-use within
///   this one session's lifetime is the right trust model, not a
///   downgrade from it.
/// - `BatchMode=yes` -- never fall back to an interactive prompt (a
///   password, a passphrase, a host-key confirmation); fail closed
///   instead, since there is no operator present to answer one.
///
/// Does **not** include the port flag -- `ssh` and `scp` spell it
/// differently (`-p` vs `-P`), so [`ssh_option_args`] and
/// [`scp_option_args`] each add their own.
fn common_option_args(endpoint: &GuestEndpoint<'_>) -> Vec<String> {
    vec![
        "-i".to_string(),
        endpoint.private_key_path.display().to_string(),
        "-o".to_string(),
        "IdentitiesOnly=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
    ]
}

/// Full option set for an `ssh` invocation, including `-p <port>`.
pub fn ssh_option_args(endpoint: &GuestEndpoint<'_>) -> Vec<String> {
    let mut args = common_option_args(endpoint);
    args.push("-p".to_string());
    args.push(endpoint.port.to_string());
    args
}

/// Full option set for an `scp` invocation, including `-P <port>` --
/// `scp` uses the uppercase flag for the same thing `ssh` spells `-p`.
pub fn scp_option_args(endpoint: &GuestEndpoint<'_>) -> Vec<String> {
    let mut args = common_option_args(endpoint);
    args.push("-P".to_string());
    args.push(endpoint.port.to_string());
    args
}

/// Shell-quotes a single token for safe inclusion in the remote command
/// string OpenSSH hands to the guest's login shell. Unlike `podman
/// exec`'s pure-argv model, OpenSSH concatenates every argument after the
/// destination into one string and sends it as-is for the remote shell
/// to interpret -- so a value containing shell metacharacters would
/// otherwise be reinterpreted rather than passed through literally.
/// Wrapping in single quotes and escaping any embedded single quote (the
/// standard `'\''` technique) makes every token inert regardless of its
/// content, keeping this channel to the same "never let a string reach a
/// shell unescaped" posture the rest of this project holds
/// (`habitat-audit`'s JSON escaping, the blocklist matcher).
pub fn shell_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

pub fn build_remote_command(env: &[(&str, &str)], program: &str, args: &[&str]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(env.len() + 1 + args.len());
    for (k, v) in env {
        // `k` is always one of this crate's own fixed identifiers
        // (`GIT_AUTHOR_NAME` and friends) -- never attacker-influenced --
        // so only the value needs quoting.
        parts.push(format!("{k}={}", shell_quote(v)));
    }
    parts.push(shell_quote(program));
    parts.extend(args.iter().map(|a| shell_quote(a)));
    parts.join(" ")
}

/// Builds the full `ssh` argv for one `exec_with_env` call -- exposed so
/// external test targets can build the exact expected invocation for a
/// `FakeCommandRunner` mock in one call, rather than re-deriving
/// [`ssh_option_args`]/[`build_remote_command`]'s combination themselves.
pub fn ssh_exec_args(
    endpoint: &GuestEndpoint<'_>,
    env: &[(&str, &str)],
    program: &str,
    args: &[&str],
) -> Vec<String> {
    let mut full = ssh_option_args(endpoint);
    full.push(format!("{GUEST_SSH_USER}@{}", endpoint.host));
    full.push(build_remote_command(env, program, args));
    full
}

impl<'a, R: CommandRunner> GuestExecRunner<'a, R> {
    pub fn new(inner: &'a R, endpoint: GuestEndpoint<'a>) -> Self {
        GuestExecRunner { inner, endpoint }
    }

    /// `ssh [options] habitat@<addr> '<shell-quoted env prefix + program + args>'`.
    /// The env prefix is how a guest-side git commit gets the fixed
    /// synthetic author/committer identity (`crate::gitseed`'s constants)
    /// without this crate ever needing to set an environment variable on
    /// the *host* process for a guest-side command.
    pub fn exec_with_env(
        &self,
        env: &[(&str, &str)],
        program: &str,
        args: &[&str],
    ) -> io::Result<Output> {
        let full = ssh_exec_args(&self.endpoint, env, program, args);
        let arg_refs: Vec<&str> = full.iter().map(String::as_str).collect();
        self.inner.run("ssh", &arg_refs)
    }

    pub fn exec(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        self.exec_with_env(&[], program, args)
    }

    /// `scp [options] <host_path> habitat@<host>:<guest_path>` -- the
    /// only way a host-generated patch file reaches the guest
    /// filesystem for this sync mechanism; never a live bind-mount.
    pub fn copy_in(&self, host_path: &str, guest_path: &str) -> io::Result<Output> {
        let mut full = scp_option_args(&self.endpoint);
        full.push(host_path.to_string());
        full.push(format!(
            "{GUEST_SSH_USER}@{}:{guest_path}",
            self.endpoint.host
        ));
        let arg_refs: Vec<&str> = full.iter().map(String::as_str).collect();
        self.inner.run("scp", &arg_refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::testing::FakeCommandRunner;
    use std::path::PathBuf;

    fn endpoint(key_path: &Path) -> GuestEndpoint<'_> {
        GuestEndpoint {
            host: "127.0.0.1",
            port: 34567,
            private_key_path: key_path,
        }
    }

    #[test]
    fn shell_quote_makes_embedded_single_quotes_and_metacharacters_inert() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(shell_quote("a; b"), "'a; b'");
    }

    #[test]
    fn exec_builds_the_expected_ssh_invocation() {
        let key_path = PathBuf::from("/tmp/habitat-guest-exec-test-key");
        let runner = FakeCommandRunner::default().with_ok(
            &format!(
                "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o \
                 UserKnownHostsFile=/dev/null -o BatchMode=yes -p 34567 habitat@127.0.0.1 'git' \
                 '-C' '/workspace' 'status' '--porcelain'",
                key_path.display()
            ),
            "",
        );
        let guest = GuestExecRunner::new(&runner, endpoint(&key_path));
        let output = guest
            .exec("git", &["-C", "/workspace", "status", "--porcelain"])
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn exec_with_env_prefixes_the_remote_command_with_quoted_assignments() {
        let key_path = PathBuf::from("/tmp/habitat-guest-exec-env-test-key");
        let runner = FakeCommandRunner::default().with_ok(
            &format!(
                "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o \
                 UserKnownHostsFile=/dev/null -o BatchMode=yes -p 34567 habitat@127.0.0.1 \
                 GIT_AUTHOR_NAME='Agent Habitat' 'git' 'commit'",
                key_path.display()
            ),
            "",
        );
        let guest = GuestExecRunner::new(&runner, endpoint(&key_path));
        let output = guest
            .exec_with_env(&[("GIT_AUTHOR_NAME", "Agent Habitat")], "git", &["commit"])
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn a_malicious_argument_never_escapes_its_quoting() {
        // If this argument were interpolated unquoted, the remote shell
        // would see two commands (`git status` then `rm -rf /`). Quoted,
        // it must appear as one single, inert token.
        let key_path = PathBuf::from("/tmp/habitat-guest-exec-injection-test-key");
        let runner = FakeCommandRunner::default(); // nothing configured -- we only inspect the built argv
        let guest = GuestExecRunner::new(&runner, endpoint(&key_path));
        let _ = guest.exec("git", &["status; rm -rf /"]);
        let invocations = runner.invocations.borrow();
        let last = invocations.last().unwrap();
        assert!(
            last.ends_with("'status; rm -rf /'"),
            "the malicious argument must appear as one quoted token: {last:?}"
        );
    }

    #[test]
    fn copy_in_builds_the_expected_scp_invocation() {
        let key_path = PathBuf::from("/tmp/habitat-guest-cp-test-key");
        let runner = FakeCommandRunner::default().with_ok(
            &format!(
                "scp -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o \
                 UserKnownHostsFile=/dev/null -o BatchMode=yes -P 34567 /tmp/x.patch \
                 habitat@127.0.0.1:/tmp/x.patch",
                key_path.display()
            ),
            "",
        );
        let guest = GuestExecRunner::new(&runner, endpoint(&key_path));
        let output = guest.copy_in("/tmp/x.patch", "/tmp/x.patch").unwrap();
        assert!(output.status.success());
    }
}
