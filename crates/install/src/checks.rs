//! Individual, named preflight/install checks. Each check is a small
//! function over the `Environment` seam so it fails closed on any
//! ambiguous or error condition (never "assume present", never silently
//! pass on a probe error) and names itself distinctly on failure.

use crate::environment::Environment;
use std::fmt;
use std::path::Path;

/// Identifies which specific check failed, for the operator-facing error
/// message and the audit log's `check` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckId {
    HostOs,
    Kvm,
    Podman,
    KrunRuntime,
    CrunVersion,
    Passt,
    Libkrunfw,
    Betterleaks,
}

impl CheckId {
    pub fn name(self) -> &'static str {
        match self {
            CheckId::HostOs => "host-os",
            CheckId::Kvm => "kvm",
            CheckId::Podman => "podman",
            CheckId::KrunRuntime => "krun-runtime",
            CheckId::CrunVersion => "crun-version",
            CheckId::Passt => "passt",
            CheckId::Libkrunfw => "libkrunfw",
            CheckId::Betterleaks => "betterleaks",
        }
    }
}

impl fmt::Display for CheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A failed check: which one, and why. `message` is environment-influenced
/// text -- never interpolate it into a shell.
#[derive(Debug, Clone)]
pub struct CheckFailure {
    pub check: CheckId,
    pub message: String,
}

impl fmt::Display for CheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.check, self.message)
    }
}

pub type CheckResult = Result<(), CheckFailure>;

fn fail(check: CheckId, message: impl Into<String>) -> CheckResult {
    Err(CheckFailure {
        check,
        message: message.into(),
    })
}

/// Explicit refusal on any non-Linux host (`docs/decisions/0001-host-os-layer.md`).
/// Runs first, before any other check.
pub fn host_os<E: Environment>(env: &E) -> CheckResult {
    let os = env.os_family();
    if os == "linux" {
        Ok(())
    } else {
        fail(
            CheckId::HostOs,
            format!("Agent Habitat only runs on Linux hosts; detected OS family: {os}"),
        )
    }
}

/// Real KVM / hardware-virtualization capability probe: `/dev/kvm` must be
/// openable for read+write (existence alone isn't enough -- a device node
/// can exist while the user isn't yet in the `kvm` group), and the CPU
/// must advertise a virtualization extension flag in `/proc/cpuinfo`.
pub fn kvm<E: Environment>(env: &E) -> CheckResult {
    let kvm_path = Path::new("/dev/kvm");
    if !env.path_exists(kvm_path) {
        return fail(
            CheckId::Kvm,
            "/dev/kvm does not exist -- hardware virtualization is not exposed to this host",
        );
    }
    if let Err(e) = env.can_open_read_write(kvm_path) {
        return fail(
            CheckId::Kvm,
            format!("/dev/kvm exists but could not be opened for read+write ({e}) -- likely a permissions/group issue"),
        );
    }

    let cpuinfo = match env.read_to_string(Path::new("/proc/cpuinfo")) {
        Ok(contents) => contents,
        Err(e) => {
            return fail(
                CheckId::Kvm,
                format!("could not read /proc/cpuinfo to confirm a CPU virtualization flag ({e})"),
            )
        }
    };
    let has_virt_flag = cpuinfo
        .lines()
        .filter(|line| line.starts_with("flags") || line.starts_with("Features"))
        .any(|line| {
            line.contains(" vmx")
                || line.contains(" svm")
                || line.contains("\tvmx")
                || line.contains("\tsvm")
        });
    if !has_virt_flag {
        return fail(
            CheckId::Kvm,
            "no CPU virtualization extension flag (vmx/svm) found in /proc/cpuinfo",
        );
    }
    Ok(())
}

/// Podman present and actually able to run rootless, i.e. without any
/// daemon/socket prerequisite. Shared by `habitat install` and
/// `habitat run`'s preflight subroutine.
pub fn podman<E: Environment>(env: &E) -> CheckResult {
    match env.run_command("podman", &["--version"]) {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            return fail(
                CheckId::Podman,
                format!(
                    "`podman --version` exited non-zero: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            )
        }
        Err(e) => {
            return fail(
                CheckId::Podman,
                format!("could not run `podman --version` (is podman on PATH?): {e}"),
            )
        }
    }

    match env.run_command("podman", &["info"]) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => fail(
            CheckId::Podman,
            format!(
                "`podman info` failed -- podman isn't usable in rootless mode for this user: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(e) => fail(CheckId::Podman, format!("could not run `podman info`: {e}")),
    }
}

/// The `krun` OCI runtime (shipped by the `crun-krun` package, backed by
/// libkrun) is available -- `krun` is the binary Podman actually exec's to
/// launch the session's microVM.
///
/// **The package name and the binary name are not the same** -- confirmed
/// on real Fedora hardware (`rpm -ql crun-krun` lists `/usr/bin/krun`, not
/// `/usr/bin/crun-krun`). Run `krun --version` here, never `crun-krun
/// --version`.
pub fn krun_runtime<E: Environment>(env: &E) -> CheckResult {
    match env.run_command("krun", &["--version"]) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => fail(
            CheckId::KrunRuntime,
            format!(
                "krun --version exited non-zero: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(e) => fail(
            CheckId::KrunRuntime,
            format!("krun not runnable (is the crun-krun package installed?): {e}"),
        ),
    }
}

/// The minimum `crun` version this project trusts for real sandboxed
/// networking. Pinned above crun 1.27.1 (which merely added the
/// `krun.use_passt` annotation): real Fedora 44 hardware with crun-krun
/// 1.28 accepts that annotation and boots a passt-backed guest, but every
/// SSH connection into it resets mid-handshake (RST from `pasta`'s own
/// splice, before the guest's sshd ever sees the connection). So a
/// passing check must mean "this exact trusted build," not just "new
/// enough to accept the annotation."
pub const MIN_CRUN_VERSION_FOR_PASST: (u32, u32, u32) = (1, 29, 1);

/// `krun`'s underlying `crun` version is at least
/// [`MIN_CRUN_VERSION_FOR_PASST`], i.e. confirmed capable of real
/// `passt`-backed networking rather than silently falling back to
/// libkrun's default TSI mode, or accepting `krun.use_passt` but still
/// resetting every guest SSH connection.
///
/// **Separate check from [`krun_runtime`]**: `krun --version` succeeding
/// says nothing about whether the build is new enough for real
/// networking. Confirmed on real AlmaLinux 10.2 hardware: its
/// `crun-krun-1.27-2.el10_2` package is behind this cutoff, accepts
/// `--network pasta` without error, and the guest silently boots under
/// TSI instead (no virtio-net device at all) -- with no error message
/// pointing at the cause.
///
/// Parses `krun --version`'s own output rather than querying a package
/// manager, since a from-source or manually-installed build has no
/// package-manager record to query.
pub fn crun_version<E: Environment>(env: &E) -> CheckResult {
    let output = match env.run_command("krun", &["--version"]) {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            return fail(
                CheckId::CrunVersion,
                format!(
                    "krun --version exited non-zero: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            )
        }
        Err(e) => {
            return fail(
                CheckId::CrunVersion,
                format!("could not run krun --version: {e}"),
            )
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(version) = parse_crun_version(&stdout) else {
        return fail(
            CheckId::CrunVersion,
            format!(
                "could not parse a version number from krun --version's output: {:?}",
                stdout.lines().next().unwrap_or_default()
            ),
        );
    };
    if version >= MIN_CRUN_VERSION_FOR_PASST {
        Ok(())
    } else {
        fail(
            CheckId::CrunVersion,
            format!(
                "crun {}.{}.{} is older than the {}.{}.{} build this project trusts for real \
                 sandboxed networking -- an older build may silently boot under libkrun's \
                 default TSI networking instead of real passt-backed networking (if it predates \
                 the krun.use_passt annotation entirely), or may accept that annotation but \
                 still reset every guest SSH connection (confirmed on real Fedora 44 hardware \
                 running crun-krun 1.28) -- either way, with no error message pointing at why",
                version.0,
                version.1,
                version.2,
                MIN_CRUN_VERSION_FOR_PASST.0,
                MIN_CRUN_VERSION_FOR_PASST.1,
                MIN_CRUN_VERSION_FOR_PASST.2,
            ),
        )
    }
}

/// Parses `"crun version X.Y.Z"` into `(major, minor, patch)`. A missing
/// patch component is treated as `.0` -- crun's own version scheme drops
/// a trailing `.0` on whole-minor releases.
fn parse_crun_version(text: &str) -> Option<(u32, u32, u32)> {
    let line = text.lines().next()?;
    let version_str = line.strip_prefix("crun version ")?;
    let mut parts = version_str.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// `passt` -- the userspace program that gives the guest its real virtual
/// network interface (`docs/decisions/0004-networking-layer.md`) -- is
/// installed and runnable.
///
/// **Separate check from [`crun_version`]**: that only confirms crun-krun
/// is new enough to hand off to `passt`, not that the `passt`/`pasta`
/// package is actually installed -- podman's `--network pasta` driver
/// only recommends it, doesn't hard-require it on every distro.
pub fn passt<E: Environment>(env: &E) -> CheckResult {
    match env.run_command("passt", &["--version"]) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => fail(
            CheckId::Passt,
            format!(
                "passt --version exited non-zero: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(e) => fail(
            CheckId::Passt,
            format!("passt not runnable (is the passt package installed?): {e}"),
        ),
    }
}

/// `libkrunfw` (the shared library bundling the guest kernel `libkrun`
/// boots) is resolvable by the dynamic linker.
///
/// **Separate check from [`krun_runtime`]**: confirmed on real AlmaLinux
/// 10.2 hardware -- `krun --version` succeeds even with `libkrunfw`
/// completely absent, since that code path never dlopen's it. Without
/// this check the first symptom is a session launch itself failing
/// ("Couldn't find or load libkrunfw.so.5").
///
/// **Not an RPM dependency**: the EPEL build of `libkrun` for AlmaLinux
/// 10 declares no RPM `Requires` on `libkrunfw` (it's dlopen'd, not
/// linked), and EPEL carries no `libkrunfw` package to depend on anyway.
/// See `package_manager::LIBKRUNFW_FALLBACK_URL` for the install-time fix.
///
/// Checked via `ldconfig -p` rather than `ldd krun` (dlopen'd, not a
/// direct ELF dependency) or a fixed path guess.
pub fn libkrunfw<E: Environment>(env: &E) -> CheckResult {
    match env.run_command("ldconfig", &["-p"]) {
        Ok(output) if output.status.success() => {
            if String::from_utf8_lossy(&output.stdout).contains("libkrunfw") {
                Ok(())
            } else {
                fail(
                    CheckId::Libkrunfw,
                    "libkrunfw not found by the dynamic linker (ldconfig -p) -- krun needs \
                     this to actually boot a session's microVM, even though `krun --version` \
                     alone doesn't exercise it",
                )
            }
        }
        Ok(output) => fail(
            CheckId::Libkrunfw,
            format!(
                "`ldconfig -p` exited non-zero: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(e) => fail(
            CheckId::Libkrunfw,
            format!("could not run `ldconfig -p` to check for libkrunfw: {e}"),
        ),
    }
}

/// The `betterleaks` binary (content-based secrets scanning) on `PATH`.
/// Only run when the project's config has `secrets_scan.content` enabled
/// (`crate::preflight::run_preflight` gates the call on that flag).
///
/// Absence is a hard preflight failure, never a silent skip -- scanning
/// that's supposed to be on must not quietly become a no-op.
pub fn betterleaks<E: Environment>(env: &E) -> CheckResult {
    match env.run_command("betterleaks", &["--version"]) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => fail(
            CheckId::Betterleaks,
            format!(
                "betterleaks --version exited non-zero: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(e) => fail(
            CheckId::Betterleaks,
            format!(
                "betterleaks not found on PATH, but secrets_scan.content is enabled for this \
                 project -- install betterleaks or set secrets_scan.content: disabled in the \
                 project's checked-in config: {e}"
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::testing::FakeEnvironment;
    use std::io::ErrorKind;

    #[test]
    fn host_os_passes_on_linux() {
        assert!(host_os(&FakeEnvironment::linux()).is_ok());
    }

    #[test]
    fn host_os_refuses_non_linux() {
        let env = FakeEnvironment {
            os_family: "macos".to_string(),
            ..Default::default()
        };
        let err = host_os(&env).unwrap_err();
        assert_eq!(err.check, CheckId::HostOs);
        assert!(err.message.contains("macos"));
    }

    #[test]
    fn kvm_fails_when_device_missing() {
        let env = FakeEnvironment::linux();
        let err = kvm(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Kvm);
        assert!(err.message.contains("/dev/kvm"));
    }

    #[test]
    fn kvm_fails_when_device_present_but_permission_denied() {
        let env = FakeEnvironment::linux()
            .with_unopenable_path("/dev/kvm", ErrorKind::PermissionDenied)
            .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc");
        let err = kvm(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Kvm);
        assert!(err.message.contains("permissions"));
    }

    #[test]
    fn kvm_fails_when_no_cpu_virt_flag() {
        let env = FakeEnvironment::linux()
            .with_existing_path("/dev/kvm")
            .with_file("/proc/cpuinfo", "flags\t\t: fpu vme tsc");
        let err = kvm(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Kvm);
        assert!(err.message.contains("vmx/svm"));
    }

    #[test]
    fn kvm_passes_with_device_and_virt_flag() {
        let env = FakeEnvironment::linux()
            .with_existing_path("/dev/kvm")
            .with_file("/proc/cpuinfo", "flags\t\t: fpu vme vmx tsc");
        assert!(kvm(&env).is_ok());
    }

    #[test]
    fn podman_fails_when_missing() {
        let env = FakeEnvironment::linux();
        let err = podman(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Podman);
    }

    #[test]
    fn podman_fails_when_info_unreachable() {
        let env = FakeEnvironment::linux()
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_failure("podman info", "cannot re-exec process");
        let err = podman(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Podman);
        assert!(err.message.contains("rootless"));
    }

    #[test]
    fn podman_passes_when_fully_reachable() {
        let env = FakeEnvironment::linux()
            .with_command_ok("podman --version", "podman version 5.0.0")
            .with_command_ok("podman info", "host: ...");
        assert!(podman(&env).is_ok());
    }

    #[test]
    fn krun_runtime_fails_when_missing() {
        let env = FakeEnvironment::linux();
        let err = krun_runtime(&env).unwrap_err();
        assert_eq!(err.check, CheckId::KrunRuntime);
    }

    #[test]
    fn krun_runtime_passes_when_present() {
        let env = FakeEnvironment::linux().with_command_ok("krun --version", "krun 1.14");
        assert!(krun_runtime(&env).is_ok());
    }

    #[test]
    fn crun_version_fails_when_older_than_the_annotation_cutoff() {
        let env = FakeEnvironment::linux().with_command_ok(
            "krun --version",
            "crun version 1.27\ncommit: a718a92cc9a94955a5a550b6fdec1378c247ec50\n",
        );
        let err = crun_version(&env).unwrap_err();
        assert_eq!(err.check, CheckId::CrunVersion);
        assert!(err.message.contains("krun.use_passt"));
    }

    #[test]
    fn crun_version_fails_when_new_enough_for_the_annotation_but_older_than_the_pinned_build() {
        let env = FakeEnvironment::linux()
            .with_command_ok("krun --version", "crun version 1.28\ncommit: abc\n");
        let err = crun_version(&env).unwrap_err();
        assert_eq!(err.check, CheckId::CrunVersion);
    }

    #[test]
    fn crun_version_passes_at_exactly_the_pinned_build() {
        let env = FakeEnvironment::linux()
            .with_command_ok("krun --version", "crun version 1.29.1\ncommit: abc\n");
        assert!(crun_version(&env).is_ok());
    }

    #[test]
    fn crun_version_passes_when_newer_than_the_pinned_build() {
        let env = FakeEnvironment::linux().with_command_ok(
            "krun --version",
            "crun version 1.30.0\ncommit: f0d911de5587342cfeb16473bf32ecdfeaf25957\n",
        );
        assert!(crun_version(&env).is_ok());
    }

    #[test]
    fn crun_version_fails_closed_on_an_unparseable_banner() {
        let env = FakeEnvironment::linux().with_command_ok("krun --version", "not a version line");
        let err = crun_version(&env).unwrap_err();
        assert_eq!(err.check, CheckId::CrunVersion);
    }

    #[test]
    fn crun_version_fails_closed_when_krun_is_missing() {
        let env = FakeEnvironment::linux();
        let err = crun_version(&env).unwrap_err();
        assert_eq!(err.check, CheckId::CrunVersion);
    }

    #[test]
    fn parse_crun_version_treats_a_missing_patch_as_zero() {
        assert_eq!(
            parse_crun_version("crun version 1.27\ncommit: abc"),
            Some((1, 27, 0))
        );
    }

    #[test]
    fn passt_fails_when_missing() {
        let env = FakeEnvironment::linux();
        let err = passt(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Passt);
    }

    #[test]
    fn passt_fails_when_version_exits_non_zero() {
        let env = FakeEnvironment::linux()
            .with_command_failure("passt --version", "passt: unrecognized option");
        let err = passt(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Passt);
    }

    #[test]
    fn passt_passes_when_present() {
        let env = FakeEnvironment::linux().with_command_ok("passt --version", "passt 0.0~git\n");
        assert!(passt(&env).is_ok());
    }

    #[test]
    fn libkrunfw_fails_when_ldconfig_does_not_list_it() {
        let env = FakeEnvironment::linux().with_command_ok(
            "ldconfig -p",
            "\tlibkrun.so.1 (libc6,x86-64) => /lib64/libkrun.so.1\n",
        );
        let err = libkrunfw(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Libkrunfw);
    }

    #[test]
    fn libkrunfw_fails_closed_when_ldconfig_itself_is_missing() {
        let env = FakeEnvironment::linux();
        let err = libkrunfw(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Libkrunfw);
    }

    #[test]
    fn libkrunfw_passes_when_ldconfig_lists_it() {
        let env = FakeEnvironment::linux().with_command_ok(
            "ldconfig -p",
            "\tlibkrunfw.so.5 (libc6,x86-64) => /lib64/libkrunfw.so.5\n",
        );
        assert!(libkrunfw(&env).is_ok());
    }

    #[test]
    fn betterleaks_fails_when_missing() {
        let env = FakeEnvironment::linux();
        let err = betterleaks(&env).unwrap_err();
        assert_eq!(err.check, CheckId::Betterleaks);
        assert!(err.message.contains("secrets_scan.content"));
    }

    #[test]
    fn betterleaks_passes_when_present() {
        let env =
            FakeEnvironment::linux().with_command_ok("betterleaks --version", "betterleaks 0.4.0");
        assert!(betterleaks(&env).is_ok());
    }
}
