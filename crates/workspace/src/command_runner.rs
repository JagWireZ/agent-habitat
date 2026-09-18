//! Seam between this crate's disk-build pipeline and the external
//! commands it shells out to (`git`, `mke2fs`, `debugfs`), mirroring
//! `habitat-install`'s `Environment` seam so error-handling paths can be
//! unit-tested without actually breaking those tools on the test machine.
//!
//! Unlike `habitat-install`'s KVM/Podman/krun checks, `git`/e2fsprogs have
//! no real-hardware dependency, so exit-gate and adversarial tests run
//! them for real via `SystemCommandRunner`; `FakeCommandRunner` is only
//! for unit tests that need to exercise a command failing.

use std::io;
use std::process::Output;

/// Runs an external command to completion. Returns `Err` only if the
/// program could not be started; a nonzero exit is still `Ok(Output)`
/// with `status.success() == false`, which callers must check -- same
/// contract as `habitat_install::Environment::run_command`.
pub trait CommandRunner {
    /// Equivalent to `run_with_env(&[], program, args)`, for callers with
    /// no env concerns.
    fn run(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        self.run_with_env(&[], program, args)
    }

    /// Runs `program` with `args`, plus `env` on top of this process's
    /// own environment. Not defaulted to plain `run`, so every real
    /// implementation must decide explicitly whether it honors `env`
    /// (e.g. `GIT_CEILING_DIRECTORIES`, see `crate::patch::git_apply_ceiling`)
    /// rather than silently ignoring it.
    fn run_with_env(&self, env: &[(&str, &str)], program: &str, args: &[&str])
        -> io::Result<Output>;
}

/// The real, unmocked runner.
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run_with_env(
        &self,
        env: &[(&str, &str)],
        program: &str,
        args: &[&str],
    ) -> io::Result<Output> {
        std::process::Command::new(program)
            .args(args)
            .envs(env.iter().map(|(k, v)| (*k, *v)))
            .output()
    }
}

pub mod testing {
    //! An in-memory `CommandRunner` for tests that need to exercise a
    //! command failing or being absent. Not `#[cfg(test)]`-gated so
    //! `tests/unit/workspace/` can use it too.

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
        /// Every invocation passed to `run`, in order -- lets a test assert
        /// exactly what was invoked. Mirrors `habitat-vm`'s `FakeCommandRunner`.
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

        /// A non-zero exit with `stdout` set rather than `stderr` -- for a
        /// scanner reporting findings, as opposed to [`Self::with_failure`]'s
        /// "the tool itself broke" shape.
        pub fn with_findings(mut self, invocation: &str, stdout: &str) -> Self {
            self.outcomes.insert(
                invocation.to_string(),
                FakeOutcome {
                    success: false,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
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
        /// Ignores `env` entirely -- no fake-runner test needs to assert
        /// on it today, only on which program+args ran.
        fn run_with_env(
            &self,
            _env: &[(&str, &str)],
            program: &str,
            args: &[&str],
        ) -> io::Result<Output> {
            let key = Self::key(program, args);
            self.invocations.borrow_mut().push(key.clone());
            match self.outcomes.get(&key) {
                Some(outcome) => Ok(Output {
                    // Shift into bits 8-15 (WEXITSTATUS) so `.code()` sees a
                    // real exit code 1, not a signal termination (`None`).
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
