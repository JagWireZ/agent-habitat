//! Individual, named preflight/install checks. Each check is a small
//! function over the `Environment` seam so it fails closed on any
//! ambiguous or error condition (never "assume present", never silently
//! pass on a probe error) and names itself distinctly on failure.

use crate::environment::Environment;
use std::fmt;
use std::path::Path;

/// Identifies which specific check failed -- this is what gets named in
/// the operator-facing error message and the audit log's `check` field,
/// never a generic "preflight failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckId {
    HostOs,
    Kvm,
    ContainerdNerdctl,
    KataFirecracker,
}

impl CheckId {
    pub fn name(self) -> &'static str {
        match self {
            CheckId::HostOs => "host-os",
            CheckId::Kvm => "kvm",
            CheckId::ContainerdNerdctl => "containerd-nerdctl",
            CheckId::KataFirecracker => "kata-firecracker",
        }
    }
}

impl fmt::Display for CheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A failed check: which one, and why (attacker/environment-influenced --
/// treat `message` as untrusted text, never interpolate it into a shell).
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

/// Explicit refusal on any non-Linux host. This runs first, before any
/// other check, in both `habitat install` and `habitat run`'s preflight
/// subroutine (AGENTS.md host-Linux-only decision,
/// `docs/decisions/0001-linux-only-host-in-v1.md`) -- "explicitly refuses,
/// not best effort".
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
/// openable for read+write (existence alone is not enough -- a device node
/// can exist while permission is denied), and the CPU must advertise a
/// virtualization extension flag in `/proc/cpuinfo`. Any error reading
/// either signal fails the check closed rather than assuming success.
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

/// containerd reachable + nerdctl present and able to talk to it. Shared
/// by `habitat install` and `habitat run`'s preflight subroutine -- one
/// implementation, not a re-derived duplicate per file-structure.md's
/// "shared, not per-domain" rule (applied here to check logic, not just
/// policy data).
pub fn containerd_nerdctl<E: Environment>(env: &E) -> CheckResult {
    let socket_candidates = [
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock",
    ];
    let socket_present = socket_candidates
        .iter()
        .any(|p| env.path_exists(Path::new(p)));
    if !socket_present {
        return fail(
            CheckId::ContainerdNerdctl,
            "containerd socket not found at /run/containerd/containerd.sock (or /var/run equivalent) -- is containerd installed and running?",
        );
    }

    match env.run_command("nerdctl", &["--version"]) {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            return fail(
                CheckId::ContainerdNerdctl,
                format!(
                    "`nerdctl --version` exited non-zero: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            )
        }
        Err(e) => {
            return fail(
                CheckId::ContainerdNerdctl,
                format!("could not run `nerdctl --version` (is nerdctl on PATH?): {e}"),
            )
        }
    }

    match env.run_command("nerdctl", &["info"]) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => fail(
            CheckId::ContainerdNerdctl,
            format!(
                "nerdctl could not reach containerd (`nerdctl info` failed): {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(e) => fail(
            CheckId::ContainerdNerdctl,
            format!("could not run `nerdctl info`: {e}"),
        ),
    }
}

/// Kata Containers + Firecracker availability: the Kata v2 shim binary
/// must be on PATH (this is what containerd actually exec's when a
/// container is launched with the kata runtime, so its absence means the
/// runtime cannot start regardless of what containerd's config claims),
/// and the Firecracker binary must be present and runnable.
pub fn kata_firecracker<E: Environment>(env: &E) -> CheckResult {
    match env.run_command("containerd-shim-kata-v2", &["--version"]) {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            return fail(
                CheckId::KataFirecracker,
                format!(
                    "containerd-shim-kata-v2 --version exited non-zero: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            )
        }
        Err(e) => {
            return fail(
                CheckId::KataFirecracker,
                format!(
                    "containerd-shim-kata-v2 not runnable (is Kata Containers installed?): {e}"
                ),
            )
        }
    }

    match env.run_command("firecracker", &["--version"]) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => fail(
            CheckId::KataFirecracker,
            format!(
                "firecracker --version exited non-zero: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ),
        Err(e) => fail(
            CheckId::KataFirecracker,
            format!("firecracker not runnable (is it installed and on PATH?): {e}"),
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
    fn containerd_nerdctl_fails_when_socket_absent() {
        let env = FakeEnvironment::linux();
        let err = containerd_nerdctl(&env).unwrap_err();
        assert_eq!(err.check, CheckId::ContainerdNerdctl);
        assert!(err.message.contains("socket"));
    }

    #[test]
    fn containerd_nerdctl_fails_when_nerdctl_missing() {
        let env = FakeEnvironment::linux().with_existing_path("/run/containerd/containerd.sock");
        let err = containerd_nerdctl(&env).unwrap_err();
        assert_eq!(err.check, CheckId::ContainerdNerdctl);
    }

    #[test]
    fn containerd_nerdctl_fails_when_info_unreachable() {
        let env = FakeEnvironment::linux()
            .with_existing_path("/run/containerd/containerd.sock")
            .with_command_ok("nerdctl --version", "nerdctl 1.7.0")
            .with_command_failure("nerdctl info", "failed to dial containerd socket");
        let err = containerd_nerdctl(&env).unwrap_err();
        assert_eq!(err.check, CheckId::ContainerdNerdctl);
        assert!(err.message.contains("containerd"));
    }

    #[test]
    fn containerd_nerdctl_passes_when_fully_reachable() {
        let env = FakeEnvironment::linux()
            .with_existing_path("/run/containerd/containerd.sock")
            .with_command_ok("nerdctl --version", "nerdctl 1.7.0")
            .with_command_ok("nerdctl info", "Server: ...");
        assert!(containerd_nerdctl(&env).is_ok());
    }

    #[test]
    fn kata_firecracker_fails_when_shim_missing() {
        let env = FakeEnvironment::linux();
        let err = kata_firecracker(&env).unwrap_err();
        assert_eq!(err.check, CheckId::KataFirecracker);
    }

    #[test]
    fn kata_firecracker_fails_when_shim_present_but_firecracker_missing() {
        let env = FakeEnvironment::linux()
            .with_command_ok("containerd-shim-kata-v2 --version", "kata-shim v2.0.0");
        let err = kata_firecracker(&env).unwrap_err();
        assert_eq!(err.check, CheckId::KataFirecracker);
        assert!(err.message.contains("firecracker"));
    }

    #[test]
    fn kata_firecracker_passes_when_both_present() {
        let env = FakeEnvironment::linux()
            .with_command_ok("containerd-shim-kata-v2 --version", "kata-shim v2.0.0")
            .with_command_ok("firecracker --version", "Firecracker v1.7.0");
        assert!(kata_firecracker(&env).is_ok());
    }

    // The Phase 1 exit-gate scenarios (KVM-absent reported not-false-positive,
    // broken-Kata-install fails closed, install-run-twice-no-change) are
    // black-box tests of this crate's contract with the rest of the system,
    // not pure internal logic -- per file-structure.md they live under
    // `tests/unit/install/`, not inline here.
}
