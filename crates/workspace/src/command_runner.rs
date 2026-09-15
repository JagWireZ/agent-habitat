//! Seam between this crate's disk-build pipeline and the external
//! commands it shells out to (`git`, `mke2fs`, `debugfs`), mirroring
//! `habitat-install`'s `Environment` seam so pure error-handling paths
//! (a command missing, a command failing) can be unit-tested without
//! actually breaking those tools on the machine running the tests.
//!
//! Unlike `habitat-install`'s KVM/Podman/krun checks, the tools this
//! crate shells out to (`git`, e2fsprogs' `mke2fs`/`debugfs`) are
//! ordinary, widely-available Linux tooling with no real-hardware
//! dependency -- so the exit-gate and adversarial tests for this phase
//! run them for real (`SystemCommandRunner`) rather than deferring to a
//! `tests/manual/` runbook the way Phase 3/5's KVM-dependent tests must.
//! `FakeCommandRunner` exists only for the narrower unit tests that need
//! to exercise a command failing.

use std::io;
use std::process::Output;

/// Runs an external command to completion and returns its output.
/// Returns `Err` if the program could not even be started (e.g. not
/// found on `PATH`); a nonzero exit is still `Ok(Output)` with
/// `status.success() == false`, which callers must check -- same
/// contract as `habitat_install::Environment::run_command`.
pub trait CommandRunner {
    /// Runs `program` with `args`, inheriting this process's own
    /// environment unchanged. Equivalent to `run_with_env(&[], program,
    /// args)` -- kept as a separate method (rather than making every
    /// call site pass `&[]`) purely for callers that have no env
    /// concerns at all.
    fn run(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        self.run_with_env(&[], program, args)
    }

    /// Runs `program` with `args`, plus `env` set on top of this
    /// process's own environment. Deliberately **not** defaulted to
    /// silently ignore `env` and fall back to plain `run` -- a caller
    /// that requests `GIT_CEILING_DIRECTORIES` (see
    /// `crate::patch::git_apply_ceiling`) to stop `git apply` from
    /// walking into an unrelated enclosing repository needs to know, at
    /// compile time, whether its runner actually honors that or would
    /// silently reproduce the exact bug the env var exists to prevent.
    /// Every real implementation must decide this explicitly.
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
    //! command failing or being absent, without actually breaking `git`
    //! or e2fsprogs on the machine running the tests. Not
    //! `#[cfg(test)]`-gated so `tests/unit/workspace/` (an external
    //! dependent of this crate) can use it too.

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
        /// that a true no-op sync round never goes beyond one status
        /// check. Mirrors `habitat-vm`'s `FakeCommandRunner`.
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

        /// A non-zero exit (status code 1) with `stdout` set rather than
        /// `stderr` -- for exercising a scanner that reports findings (or
        /// garbled/ambiguous output) on its findings-present exit code,
        /// as opposed to [`Self::with_failure`]'s "the tool itself broke"
        /// shape.
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
        /// on it today, only on which program+args ran (`invocations`
        /// already captures that). If a future test needs to assert a
        /// call carried a specific `GIT_CEILING_DIRECTORIES` (or any
        /// other env var), extend `key()`/`invocations` to include it
        /// rather than reaching around this method.
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
                    // Real exit codes live in bits 8-15 of the raw wait
                    // status (`WEXITSTATUS`) -- `from_raw(1)` alone would
                    // decode as a *signal*-terminated process (`.code()`
                    // returns `None`), not a normal exit with code 1.
                    // Shifting gives callers that inspect `.code()`
                    // (`crate::content_scan`, distinguishing "clean" from
                    // "findings present" from "scanner error" by exit
                    // code) a faithful fake, while `.success()` (`== 0`)
                    // behaves exactly as before either way.
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
