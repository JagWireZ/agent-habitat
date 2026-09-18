//! Seam between this crate's launcher and the external `podman` command,
//! mirroring `habitat-install`'s `Environment` and `habitat-workspace`'s
//! `CommandRunner` seams so argv construction and error handling stay
//! unit-testable without real Podman/krun/KVM. The actually-booted case
//! is `tests/manual`'s job (`tests/manual/README.md`).

use std::io;
use std::process::Output;

/// Runs an external command to completion. `Err` means the program
/// couldn't even be started; a nonzero exit is still `Ok(Output)` with
/// `status.success() == false`, which callers must check.
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
    //! In-memory `CommandRunner` for exercising a `podman` invocation
    //! succeeding, failing, or being absent, without real Podman/KVM.
    //! Not `#[cfg(test)]`-gated so external dependents (`tests/unit/vm/`,
    //! `tests/adversarial/`) can use it too.

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
        /// Invocations passed to `run`, in order, for tests to assert against.
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
                    // ExitStatus::from_raw expects the exit code in bits 8-15.
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
