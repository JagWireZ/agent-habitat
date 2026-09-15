//! The seam between this crate's sync logic and an actual running guest
//! session: every guest-side operation goes through `podman exec` /
//! `podman cp` against a live container, mirroring `habitat-vm`'s own
//! `CommandRunner` seam for the launcher rather than introducing a second
//! shelling-out mechanism. There is deliberately no bind-mount, live
//! share, or any other continuous channel here (`AGENTS.md` Section 2,
//! invariant 1) -- each guest interaction is one discrete `podman`
//! invocation, built here and run through whatever `CommandRunner` the
//! caller supplies.
//!
//! Actually exercising this against a real, booted guest needs real KVM
//! (`habitat-vm`'s own exit gate) -- so, same as
//! `crates/vm/src/launcher.rs`, the pure argv-construction logic here is
//! fully unit-tested against a `FakeCommandRunner`; the real, booted
//! round-trip is `tests/manual/validate-sync.sh`'s job.

use crate::command_runner::CommandRunner;
use habitat_vm::session::SessionId;
use std::io;
use std::process::Output;

/// Runs commands *inside* one running guest session via `podman exec`
/// (and copies a file in via `podman cp`), through whatever
/// `CommandRunner` the caller supplies for the actual `podman`
/// invocation -- this struct never shells out on its own, it only builds
/// the right argv and delegates.
pub struct GuestExecRunner<'a, R: CommandRunner> {
    inner: &'a R,
    session_id: &'a SessionId,
}

impl<'a, R: CommandRunner> GuestExecRunner<'a, R> {
    pub fn new(inner: &'a R, session_id: &'a SessionId) -> Self {
        GuestExecRunner { inner, session_id }
    }

    /// `podman exec [--env K=V ...] <session> <program> <args...>`. The
    /// `--env` flags are how a guest-side git commit gets the fixed
    /// synthetic author/committer identity (`crate::gitseed`'s constants)
    /// without this crate ever needing to read or set an environment
    /// variable on the *host* process for a guest-side command.
    pub fn exec_with_env(
        &self,
        env: &[(&str, &str)],
        program: &str,
        args: &[&str],
    ) -> io::Result<Output> {
        let mut full: Vec<String> = vec!["exec".to_string()];
        for (k, v) in env {
            full.push("--env".to_string());
            full.push(format!("{k}={v}"));
        }
        full.push(self.session_id.to_string());
        full.push(program.to_string());
        full.extend(args.iter().map(|a| a.to_string()));
        let arg_refs: Vec<&str> = full.iter().map(String::as_str).collect();
        self.inner.run("podman", &arg_refs)
    }

    pub fn exec(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        self.exec_with_env(&[], program, args)
    }

    /// `podman cp <host_path> <session>:<guest_path>` -- the only way a
    /// host-generated patch file reaches the guest filesystem for this
    /// sync mechanism; never a live bind-mount.
    pub fn copy_in(&self, host_path: &str, guest_path: &str) -> io::Result<Output> {
        self.inner.run(
            "podman",
            &[
                "cp",
                host_path,
                &format!("{}:{}", self.session_id, guest_path),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::testing::FakeCommandRunner;

    #[test]
    fn exec_builds_the_expected_podman_exec_argv() {
        let session_id = SessionId::from_name("habitat-guest-exec-test").unwrap();
        let runner = FakeCommandRunner::default().with_ok(
            "podman exec habitat-guest-exec-test git -C /workspace status --porcelain",
            "",
        );
        let guest = GuestExecRunner::new(&runner, &session_id);
        let output = guest
            .exec("git", &["-C", "/workspace", "status", "--porcelain"])
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn exec_with_env_puts_env_flags_before_the_session_name() {
        let session_id = SessionId::from_name("habitat-guest-exec-env-test").unwrap();
        let runner = FakeCommandRunner::default().with_ok(
            "podman exec --env GIT_AUTHOR_NAME=Agent Habitat habitat-guest-exec-env-test git commit",
            "",
        );
        let guest = GuestExecRunner::new(&runner, &session_id);
        let output = guest
            .exec_with_env(&[("GIT_AUTHOR_NAME", "Agent Habitat")], "git", &["commit"])
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn copy_in_builds_the_expected_podman_cp_argv() {
        let session_id = SessionId::from_name("habitat-guest-cp-test").unwrap();
        let runner = FakeCommandRunner::default().with_ok(
            "podman cp /tmp/x.patch habitat-guest-cp-test:/tmp/x.patch",
            "",
        );
        let guest = GuestExecRunner::new(&runner, &session_id);
        let output = guest.copy_in("/tmp/x.patch", "/tmp/x.patch").unwrap();
        assert!(output.status.success());
    }
}
