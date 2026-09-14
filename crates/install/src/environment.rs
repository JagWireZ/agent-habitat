//! Seam between the checks in this crate and the real machine, so every
//! check in `checks.rs` can be exercised in a unit test against a fake
//! machine state (no KVM, a broken podman/krun install, a non-Linux OS)
//! without needing that hardware/software actually present in CI.
//!
//! Every method the checks themselves use (`os_family`, `path_exists`,
//! `can_open_read_write`, `read_to_string`, `run_command`) is read-only --
//! that's what lets `run_install_checks`/`run_preflight` promise they
//! never mutate the host. `run_command_inherited` is the one exception:
//! it exists solely for `installer.rs`'s explicit, opt-in auto-install
//! step, which no check calls.

use std::io;
use std::path::Path;
use std::process::Output;

/// Everything a preflight/install check needs to observe about the host.
/// `SystemEnvironment` is the real implementation; tests use `FakeEnvironment`.
pub trait Environment {
    /// The running OS family, e.g. `"linux"`, `"macos"`, `"windows"` --
    /// mirrors `std::env::consts::OS`.
    fn os_family(&self) -> &str;

    /// Whether `path` exists at all (any type).
    fn path_exists(&self, path: &Path) -> bool;

    /// Whether `path` can actually be opened for read+write access right
    /// now -- a real permission/capability probe, not just "the path
    /// exists". Used for `/dev/kvm`: the device node can exist while the
    /// current user still lacks access to it.
    fn can_open_read_write(&self, path: &Path) -> io::Result<()>;

    /// Read a small text file (e.g. `/proc/cpuinfo`) to a string.
    fn read_to_string(&self, path: &Path) -> io::Result<String>;

    /// Run an external command to completion and return its output.
    /// Returns `Err` if the program could not even be started (e.g. not
    /// found on `PATH`); a nonzero exit is still `Ok(Output)` with
    /// `status.success() == false`, which callers must check.
    fn run_command(&self, program: &str, args: &[&str]) -> io::Result<Output>;

    /// Run an external command with the child's stdin/stdout/stderr
    /// inherited from this process, rather than captured -- used only by
    /// `habitat install`'s explicit, opt-in auto-install step
    /// (`installer.rs`), never by the read-only checks in `checks.rs`.
    /// A package-manager install run as `sudo` needs the operator to see
    /// (and, for the password prompt, respond to) its live output; a
    /// captured/silent transcript would hide that. Returns `Ok(true)` on
    /// a zero exit, `Ok(false)` on non-zero, `Err` only if the program
    /// itself couldn't be started.
    fn run_command_inherited(&self, program: &str, args: &[&str]) -> io::Result<bool>;
}

/// The real, unmocked view of the current machine.
pub struct SystemEnvironment;

impl Environment for SystemEnvironment {
    fn os_family(&self) -> &str {
        std::env::consts::OS
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn can_open_read_write(&self, path: &Path) -> io::Result<()> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map(|_file| ())
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn run_command(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        std::process::Command::new(program).args(args).output()
    }

    fn run_command_inherited(&self, program: &str, args: &[&str]) -> io::Result<bool> {
        std::process::Command::new(program)
            .args(args)
            .status()
            .map(|status| status.success())
    }
}

pub mod testing {
    //! A fully in-memory `Environment` for tests. Not `#[cfg(test)]`-gated:
    //! this needs to be usable both by this crate's own inline unit tests
    //! (pure per-check logic) and by the black-box exit-gate tests under
    //! `tests/unit/install/`, which exercise this crate as an external
    //! dependency and so only see items it actually exports.

    use super::*;
    use std::collections::HashMap;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[derive(Default, Clone)]
    pub struct FakeEnvironment {
        pub os_family: String,
        /// Paths considered to exist.
        pub existing_paths: Vec<String>,
        /// Paths that exist but fail the read+write open probe, mapped to
        /// the io::ErrorKind to fail with.
        pub unopenable_paths: HashMap<String, io::ErrorKind>,
        /// Contents returned by `read_to_string`, keyed by path.
        pub file_contents: HashMap<String, String>,
        /// Canned command results, keyed by `"program arg1 arg2"`.
        pub command_results: HashMap<String, FakeCommandResult>,
        /// Canned success/failure for `run_command_inherited`, keyed the
        /// same way as `command_results`. Separate map because the two
        /// methods serve different callers (probes vs. the auto-install
        /// step) and a test should be able to configure one without
        /// implying anything about the other.
        pub inherited_command_results: HashMap<String, bool>,
        /// Every invocation passed to `run_command_inherited`, in order --
        /// lets a test assert the auto-install step actually ran (or
        /// didn't run) the commands it claims to.
        pub inherited_invocations: std::cell::RefCell<Vec<String>>,
    }

    #[derive(Clone)]
    pub struct FakeCommandResult {
        pub success: bool,
        pub stdout: String,
        pub stderr: String,
    }

    impl FakeEnvironment {
        pub fn linux() -> Self {
            FakeEnvironment {
                os_family: "linux".to_string(),
                ..Default::default()
            }
        }

        pub fn with_existing_path(mut self, path: &str) -> Self {
            self.existing_paths.push(path.to_string());
            self
        }

        pub fn with_unopenable_path(mut self, path: &str, kind: io::ErrorKind) -> Self {
            self.existing_paths.push(path.to_string());
            self.unopenable_paths.insert(path.to_string(), kind);
            self
        }

        pub fn with_file(mut self, path: &str, contents: &str) -> Self {
            self.existing_paths.push(path.to_string());
            self.file_contents
                .insert(path.to_string(), contents.to_string());
            self
        }

        pub fn with_command_ok(mut self, invocation: &str, stdout: &str) -> Self {
            self.command_results.insert(
                invocation.to_string(),
                FakeCommandResult {
                    success: true,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                },
            );
            self
        }

        pub fn with_command_failure(mut self, invocation: &str, stderr: &str) -> Self {
            self.command_results.insert(
                invocation.to_string(),
                FakeCommandResult {
                    success: false,
                    stdout: String::new(),
                    stderr: stderr.to_string(),
                },
            );
            self
        }

        pub fn with_inherited_command_ok(mut self, invocation: &str) -> Self {
            self.inherited_command_results
                .insert(invocation.to_string(), true);
            self
        }

        pub fn with_inherited_command_failure(mut self, invocation: &str) -> Self {
            self.inherited_command_results
                .insert(invocation.to_string(), false);
            self
        }

        fn invocation_key(program: &str, args: &[&str]) -> String {
            let mut key = program.to_string();
            for a in args {
                key.push(' ');
                key.push_str(a);
            }
            key
        }
    }

    impl Environment for FakeEnvironment {
        fn os_family(&self) -> &str {
            &self.os_family
        }

        fn path_exists(&self, path: &Path) -> bool {
            self.existing_paths.iter().any(|p| Path::new(p) == path)
        }

        fn can_open_read_write(&self, path: &Path) -> io::Result<()> {
            let key = path.to_string_lossy().to_string();
            if let Some(kind) = self.unopenable_paths.get(&key) {
                return Err(io::Error::new(*kind, "fake: permission probe failed"));
            }
            if self.path_exists(path) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "fake: no such path",
                ))
            }
        }

        fn read_to_string(&self, path: &Path) -> io::Result<String> {
            let key = path.to_string_lossy().to_string();
            self.file_contents
                .get(&key)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "fake: no such file"))
        }

        fn run_command(&self, program: &str, args: &[&str]) -> io::Result<Output> {
            let key = Self::invocation_key(program, args);
            match self.command_results.get(&key) {
                Some(result) => Ok(Output {
                    status: ExitStatus::from_raw(if result.success { 0 } else { 1 }),
                    stdout: result.stdout.clone().into_bytes(),
                    stderr: result.stderr.clone().into_bytes(),
                }),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("fake: command not configured: {key}"),
                )),
            }
        }

        fn run_command_inherited(&self, program: &str, args: &[&str]) -> io::Result<bool> {
            let key = Self::invocation_key(program, args);
            self.inherited_invocations.borrow_mut().push(key.clone());
            self.inherited_command_results
                .get(&key)
                .copied()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("fake: inherited command not configured: {key}"),
                    )
                })
        }
    }
}
