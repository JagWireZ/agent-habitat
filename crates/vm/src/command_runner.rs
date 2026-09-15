//! Seam between this crate's launcher and the external command it shells
//! out to (`podman`), mirroring `habitat-install`'s `Environment` seam and
//! `habitat-workspace`'s `CommandRunner` seam so command-construction and
//! error-handling logic can be unit-tested without a real Podman/krun
//! install (let alone real KVM) on the machine running the tests.
//!
//! Unlike `habitat-workspace`'s `git`/`mke2fs`/`debugfs` calls, actually
//! *launching* a session through Podman + `krun` needs real hardware
//! (KVM) this dev container and this project's CI don't have -- so this
//! seam exists precisely so the pure parts (which argv gets built, how a
//! non-zero exit or missing binary is reported, teardown's idempotency)
//! stay testable, while the actually-booted-and-escaped-from case is
//! `tests/manual`'s job (`tests/manual/README.md`).

use std::io;
use std::process::Output;

/// Runs an external command to completion and returns its output.
/// Returns `Err` if the program could not even be started (e.g. not
/// found on `PATH`); a nonzero exit is still `Ok(Output)` with
/// `status.success() == false`, which callers must check -- same
/// contract as `habitat_install::Environment::run_command` and
/// `habitat_workspace::command_runner::CommandRunner::run`.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<Output>;
}

/// The real, unmocked runner.
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        std::process::Command::new(program).args(args).output()
    }
}

pub mod testing {
    //! An in-memory `CommandRunner` for tests that need to exercise a
    //! `podman` invocation succeeding, failing, or being absent, without
    //! actually running Podman/krun (or needing KVM) on the machine
    //! running the tests. Not `#[cfg(test)]`-gated so `tests/unit/vm/`
    //! and `tests/adversarial/` (external dependents of this crate) can
    //! use it too.

    use super::*;
    use std::collections::HashMap;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[derive(Clone)]
    pub struct FakeOutcome {
        pub success: bool,
        pub stdout: String,
        pub stderr: String,
    }

    #[derive(Default, Clone)]
    pub struct FakeCommandRunner {
        outcomes: HashMap<String, FakeOutcome>,
        /// Every invocation passed to `run`, in order -- lets a test
        /// assert exactly what was (or wasn't) actually invoked, e.g.
        /// that teardown never re-invokes launch's own command.
        pub invocations: std::cell::RefCell<Vec<String>>,
    }

    impl FakeCommandRunner {
        pub fn with_ok(mut self, invocation: &str, stdout: &str) -> Self {
            self.outcomes.insert(
                invocation.to_string(),
                FakeOutcome {
                    success: true,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                },
            );
            self
        }

        pub fn with_failure(mut self, invocation: &str, stderr: &str) -> Self {
            self.outcomes.insert(
                invocation.to_string(),
                FakeOutcome {
                    success: false,
                    stdout: String::new(),
                    stderr: stderr.to_string(),
                },
            );
            self
        }

        fn key(program: &str, args: &[&str]) -> String {
            let mut key = program.to_string();
            for a in args {
                key.push(' ');
                key.push_str(a);
            }
            key
        }
    }

    impl CommandRunner for FakeCommandRunner {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<Output> {
            let key = Self::key(program, args);
            self.invocations.borrow_mut().push(key.clone());
            match self.outcomes.get(&key) {
                Some(outcome) => Ok(Output {
                    // See `habitat-workspace`'s `FakeCommandRunner` for
                    // why this shifts into bits 8-15 rather than using
                    // the raw value `1` directly.
                    status: ExitStatus::from_raw(if outcome.success { 0 } else { 1 << 8 }),
                    stdout: outcome.stdout.clone().into_bytes(),
                    stderr: outcome.stderr.clone().into_bytes(),
                }),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("fake: command not configured: {key}"),
                )),
            }
        }
    }
}
