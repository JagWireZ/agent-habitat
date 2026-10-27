//! Seam between this crate's staging pipeline and the external commands
//! it shells out to (`git`), mirroring `habitat-install`'s `Environment`
//! seam so error-handling paths can be unit-tested without actually
//! breaking those tools on the test machine.
//!
//! Unlike `habitat-install`'s KVM/Podman/krun checks, `git` has no
//! real-hardware dependency, so exit-gate and adversarial tests run it
//! for real via `SystemCommandRunner`; `FakeCommandRunner` is only for
//! unit tests that need to exercise a command failing.

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
    fn run_with_env(
        &self,
        env: &[(&str, &str)],
        program: &str,
        args: &[&str],
    ) -> io::Result<Output>;
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

    /// A `CommandRunner` that plays the part of one booted guest, backed
    /// by a real temporary directory standing in for the guest's
    /// filesystem root (guest path `/home/habitat/x` is
    /// `<root>/home/habitat/x`). It understands exactly the `ssh`/`scp`
    /// invocations `GuestExecRunner` builds for agent-state copying:
    /// `mkdir -p`, `chmod`, `head -c N -- <path>`, `scp <file>`, and
    /// `scp -r <dir>`. Anything else is an error, so a test fails loudly
    /// if the code starts issuing a command nobody modelled. `Sync`, so it
    /// also serves the threaded shell-session path.
    pub struct FakeGuest {
        root: std::path::PathBuf,
        pub invocations: std::sync::Mutex<Vec<String>>,
        /// When set, every call exits 255 -- the exit code `ssh` itself
        /// uses for a transport failure.
        pub transport_down: std::sync::atomic::AtomicBool,
    }

    impl FakeGuest {
        pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
            let root = root.into();
            std::fs::create_dir_all(&root).expect("fake guest root");
            FakeGuest {
                root,
                invocations: std::sync::Mutex::new(Vec::new()),
                transport_down: std::sync::atomic::AtomicBool::new(false),
            }
        }

        /// Where a guest-absolute path really lives on the test host.
        pub fn path(&self, guest_path: &str) -> std::path::PathBuf {
            self.root.join(guest_path.trim_start_matches('/'))
        }

        pub fn write(&self, guest_path: &str, contents: &[u8]) {
            let p = self.path(guest_path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, contents).unwrap();
        }

        pub fn read(&self, guest_path: &str) -> Option<Vec<u8>> {
            std::fs::read(self.path(guest_path)).ok()
        }

        pub fn exists(&self, guest_path: &str) -> bool {
            self.path(guest_path).exists()
        }

        fn out(code: i32, stdout: Vec<u8>, stderr: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(code << 8),
                stdout,
                stderr: stderr.as_bytes().to_vec(),
            }
        }

        /// Splits a remote command string the way the guest's shell
        /// would for the single-quote style `shell_quote` emits.
        fn unquote(cmd: &str) -> Vec<String> {
            let mut tokens = Vec::new();
            let mut cur = String::new();
            let mut in_token = false;
            let mut in_quote = false;
            let mut chars = cmd.chars().peekable();
            while let Some(c) = chars.next() {
                if in_quote {
                    if c == '\'' {
                        in_quote = false;
                    } else {
                        cur.push(c);
                    }
                } else if c == '\'' {
                    in_quote = true;
                    in_token = true;
                } else if c == '\\' {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                        in_token = true;
                    }
                } else if c == ' ' {
                    if in_token {
                        tokens.push(std::mem::take(&mut cur));
                        in_token = false;
                    }
                } else {
                    cur.push(c);
                    in_token = true;
                }
            }
            if in_token {
                tokens.push(cur);
            }
            tokens
        }

        fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> io::Result<()> {
            if src.is_dir() {
                std::fs::create_dir_all(dst)?;
                for e in std::fs::read_dir(src)? {
                    let e = e?;
                    Self::copy_tree(&e.path(), &dst.join(e.file_name()))?;
                }
                Ok(())
            } else {
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(src, dst).map(|_| ())
            }
        }

        fn run_ssh(&self, args: &[&str]) -> io::Result<Output> {
            let Some(idx) = args.iter().position(|a| a.starts_with("habitat@")) else {
                return Err(io::Error::other(
                    "fake guest: ssh without a habitat@ target",
                ));
            };
            let remote = args.get(idx + 1).copied().unwrap_or("");
            let argv = Self::unquote(remote);
            let Some((prog, rest)) = argv.split_first() else {
                return Ok(Self::out(0, Vec::new(), ""));
            };
            match prog.as_str() {
                "true" => Ok(Self::out(0, Vec::new(), "")),
                "mkdir" => {
                    for a in rest.iter().filter(|a| !a.starts_with('-')) {
                        std::fs::create_dir_all(self.path(a))?;
                    }
                    Ok(Self::out(0, Vec::new(), ""))
                }
                "chmod" => {
                    use std::os::unix::fs::PermissionsExt;
                    let Some((mode, files)) = rest.split_first() else {
                        return Ok(Self::out(1, Vec::new(), "chmod: missing operand"));
                    };
                    let mode = u32::from_str_radix(mode, 8).unwrap_or(0o600);
                    for f in files {
                        let p = self.path(f);
                        if p.exists() {
                            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode))?;
                        }
                    }
                    Ok(Self::out(0, Vec::new(), ""))
                }
                "head" => {
                    // head -c N -- <path>
                    let n: usize = rest
                        .iter()
                        .position(|a| a == "-c")
                        .and_then(|i| rest.get(i + 1))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(usize::MAX);
                    let Some(path) = rest.last() else {
                        return Ok(Self::out(1, Vec::new(), "head: missing file"));
                    };
                    match std::fs::read(self.path(path)) {
                        Ok(mut bytes) => {
                            bytes.truncate(n);
                            Ok(Self::out(0, bytes, ""))
                        }
                        Err(_) => Ok(Self::out(
                            1,
                            Vec::new(),
                            "head: can't open: No such file or directory",
                        )),
                    }
                }
                other => Err(io::Error::other(format!(
                    "fake guest: unmodelled remote command {other:?}"
                ))),
            }
        }

        fn run_scp(&self, args: &[&str]) -> io::Result<Output> {
            let recursive = args.contains(&"-r");
            let n = args.len();
            if n < 2 {
                return Err(io::Error::other(
                    "fake guest: scp needs a source and target",
                ));
            }
            let (src, target) = (args[n - 2], args[n - 1]);
            let Some((_, guest_path)) = target.split_once(':') else {
                return Err(io::Error::other("fake guest: scp target has no host:path"));
            };
            let src = std::path::Path::new(src);
            let mut dst = self.path(guest_path);
            if recursive {
                if !src.is_dir() {
                    return Ok(Self::out(1, Vec::new(), "scp: not a directory"));
                }
                if !dst.is_dir() {
                    return Ok(Self::out(1, Vec::new(), "scp: no such directory"));
                }
                dst = dst.join(src.file_name().unwrap());
            } else {
                if src.is_dir() {
                    return Ok(Self::out(1, Vec::new(), "scp: not a regular file"));
                }
                if !dst.parent().is_some_and(|p| p.is_dir()) {
                    return Ok(Self::out(1, Vec::new(), "scp: no such directory"));
                }
            }
            match Self::copy_tree(src, &dst) {
                Ok(()) => Ok(Self::out(0, Vec::new(), "")),
                Err(e) => Ok(Self::out(1, Vec::new(), &e.to_string())),
            }
        }
    }

    impl CommandRunner for FakeGuest {
        fn run_with_env(
            &self,
            _env: &[(&str, &str)],
            program: &str,
            args: &[&str],
        ) -> io::Result<Output> {
            let mut line = program.to_string();
            for a in args {
                line.push(' ');
                line.push_str(a);
            }
            self.invocations.lock().unwrap().push(line);
            if self
                .transport_down
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return Ok(Self::out(
                    255,
                    Vec::new(),
                    "ssh: connect to host: Connection refused",
                ));
            }
            match program {
                "ssh" => self.run_ssh(args),
                "scp" => self.run_scp(args),
                other => Err(io::Error::other(format!(
                    "fake guest: unmodelled program {other:?}"
                ))),
            }
        }
    }
}
