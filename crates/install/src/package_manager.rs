//! Host package-manager family detection, used only to pick the right
//! remediation command for `habitat install`'s optional auto-install step
//! (`installer.rs`) once a check has already failed. Never influences
//! whether a check passes or fails.

use crate::checks::CheckId;
use crate::environment::Environment;
use std::path::Path;

/// A family of Linux distros that share a package manager. Not a distro
/// identity in its own right -- AlmaLinux, Fedora, RHEL, Rocky, and
/// CentOS are all `Dnf`; Debian and Ubuntu are both `Apt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageFamily {
    Dnf,
    Apt,
}

/// Classifies the host by reading `ID` and `ID_LIKE` out of
/// `/etc/os-release`. Returns `None` on any host this can't confidently
/// classify -- callers must treat that as "no auto-install available
/// here," never guess a default family.
pub fn detect_package_family<E: Environment>(env: &E) -> Option<PackageFamily> {
    let contents = env.read_to_string(Path::new("/etc/os-release")).ok()?;
    classify(&contents)
}

fn classify(os_release: &str) -> Option<PackageFamily> {
    let mut id = String::new();
    let mut id_like = String::new();
    for line in os_release.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = unquote(v);
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            id_like = unquote(v);
        }
    }
    let haystack = format!("{id} {id_like}").to_lowercase();
    let tokens: Vec<&str> = haystack.split_whitespace().collect();
    if tokens
        .iter()
        .any(|t| matches!(*t, "fedora" | "rhel" | "almalinux" | "rocky" | "centos"))
    {
        Some(PackageFamily::Dnf)
    } else if tokens.iter().any(|t| matches!(*t, "debian" | "ubuntu")) {
        Some(PackageFamily::Apt)
    } else {
        None
    }
}

fn unquote(v: &str) -> String {
    v.trim().trim_matches('"').to_string()
}

/// The package to install for a failed `check` on `family` -- `None` when
/// there's no package-manager fix at all (`HostOs`/`Kvm`) or the package
/// doesn't exist for this family yet (`KrunRuntime` on `Apt`).
pub fn package_for(check: CheckId, family: PackageFamily) -> Option<&'static str> {
    match (check, family) {
        (CheckId::Podman, PackageFamily::Dnf) => Some("podman"),
        (CheckId::Podman, PackageFamily::Apt) => Some("podman"),
        (CheckId::KrunRuntime, PackageFamily::Dnf) => Some("crun-krun"),
        (CheckId::KrunRuntime, PackageFamily::Apt) => None,
        // Kept for display/testing; installer::attempt_one always uses
        // the pinned CRUN_FALLBACK_URL pair on Dnf instead (see its doc
        // comment for the real-hardware networking bug that requires it).
        (CheckId::CrunVersion, PackageFamily::Dnf) => Some("crun-krun"),
        (CheckId::CrunVersion, PackageFamily::Apt) => None,
        (CheckId::Passt, PackageFamily::Dnf) => Some("passt"),
        (CheckId::Passt, PackageFamily::Apt) => None,
        // Kept for display/testing; installer::attempt_one always uses
        // LIBKRUNFW_FALLBACK_URL on Dnf instead, same reason as above.
        (CheckId::Libkrunfw, PackageFamily::Dnf) => Some("libkrunfw"),
        (CheckId::Libkrunfw, PackageFamily::Apt) => None,
        (CheckId::HostOs, _) | (CheckId::Kvm, _) => None,
        (CheckId::Betterleaks, PackageFamily::Dnf) => Some("betterleaks"),
        (CheckId::Betterleaks, PackageFamily::Apt) => None,
    }
}

/// A pinned, real-hardware-confirmed source for `libkrunfw`, installed
/// unconditionally on every Dnf-family host: EPEL carries no `libkrunfw`
/// package under any name (`dnf install libkrunfw` there returns "No
/// match for argument"), and Fedora's own repo build isn't trusted enough
/// either (see [`CRUN_FALLBACK_URL`]).
///
/// A direct Koji URL for a Fedora 43 x86_64 build of upstream `libkrunfw`
/// v5.5.0. Confirmed on real AlmaLinux 10.2 hardware: installs cleanly,
/// resolves via `ldconfig -p` as `libkrunfw.so.5`, and a real
/// `krun`-backed `podman run` boots afterward. This is a cross-distro
/// binary stopgap, not an officially supported combination.
///
/// **This will eventually go stale** as Fedora rotates old Koji builds
/// out. If `habitat install` starts reporting this as `Failed`, check
/// <https://koji.fedoraproject.org/koji/packageinfo?packageID=35681> for
/// a current build and update this constant -- and check whether EPEL or
/// AlmaLinux has shipped a real `libkrunfw` package by then.
pub const LIBKRUNFW_FALLBACK_URL: &str =
    "https://kojipkgs.fedoraproject.org/packages/libkrunfw/5.5.0/1.fc43/x86_64/libkrunfw-5.5.0-1.fc43.x86_64.rpm";

/// Pinned Koji URLs for `crun` + `crun-krun` together, installed
/// unconditionally on every Dnf-family host, never `dnf install
/// crun-krun`. Both must be installed in the same invocation since
/// `crun-krun` needs the exact matching `crun` version.
///
/// Installed regardless of the repo's own version: real Fedora 44
/// hardware with repo `crun-krun` 1.28 passes `checks::crun_version`'s
/// gate and boots a passt-backed guest, but every SSH connection into it
/// resets mid-handshake (RST from `pasta`'s own splice). "New enough per
/// the version check" doesn't mean "free of this bug," so the pinned
/// 1.29.1 build is always used instead.
///
/// **This will eventually go stale**, same as [`LIBKRUNFW_FALLBACK_URL`].
pub const CRUN_FALLBACK_URL: &str =
    "https://kojipkgs.fedoraproject.org/packages/crun/1.29.1/1.fc43/x86_64/crun-1.29.1-1.fc43.x86_64.rpm";
pub const CRUN_KRUN_FALLBACK_URL: &str =
    "https://kojipkgs.fedoraproject.org/packages/crun/1.29.1/1.fc43/x86_64/crun-krun-1.29.1-1.fc43.x86_64.rpm";

/// The exact version [`CRUN_FALLBACK_URL`]/[`CRUN_KRUN_FALLBACK_URL`]
/// install. `installer::attempt_one` compares a host's
/// [`rpm_package_version`] of `crun-krun` against this so a host already
/// at this version or newer never gets downgraded.
pub const CRUN_PINNED_VERSION: (u32, u32, u32) = (1, 29, 1);

/// The installed version of `package` per `rpm`'s own query database --
/// `None` if it isn't installed, `rpm` isn't on PATH, or the version
/// string doesn't parse. Dnf-family only.
pub fn rpm_package_version<E: Environment>(env: &E, package: &str) -> Option<(u32, u32, u32)> {
    let output = env
        .run_command("rpm", &["-q", "--queryformat", "%{VERSION}\\n", package])
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_dotted_version(&String::from_utf8_lossy(&output.stdout))
}

/// Parses a bare `"X.Y.Z"` (or `"X.Y"`/`"X"`) version string's first line
/// into `(major, minor, patch)`, treating any missing trailing component
/// as `0`.
fn parse_dotted_version(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.lines().next()?.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// The command (program + args) that installs `packages` as root on
/// `family`, all in one invocation. Always non-interactive on the package
/// manager's own prompts (`-y`); `sudo` still prompts for a password,
/// which is why the caller runs this via `run_command_inherited`.
pub fn install_command(family: PackageFamily, packages: &[&str]) -> (&'static str, Vec<String>) {
    let manager = match family {
        PackageFamily::Dnf => "dnf",
        PackageFamily::Apt => "apt-get",
    };
    let mut args = vec![manager.to_string(), "install".to_string(), "-y".to_string()];
    args.extend(packages.iter().map(|p| p.to_string()));
    ("sudo", args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::testing::FakeEnvironment;

    #[test]
    fn detects_almalinux_as_dnf_family() {
        let env = FakeEnvironment::linux().with_file(
            "/etc/os-release",
            "NAME=\"AlmaLinux\"\nID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
        );
        assert_eq!(detect_package_family(&env), Some(PackageFamily::Dnf));
    }

    #[test]
    fn detects_fedora_as_dnf_family() {
        let env = FakeEnvironment::linux().with_file("/etc/os-release", "NAME=Fedora\nID=fedora\n");
        assert_eq!(detect_package_family(&env), Some(PackageFamily::Dnf));
    }

    #[test]
    fn detects_ubuntu_as_apt_family() {
        let env = FakeEnvironment::linux().with_file(
            "/etc/os-release",
            "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n",
        );
        assert_eq!(detect_package_family(&env), Some(PackageFamily::Apt));
    }

    #[test]
    fn detects_debian_as_apt_family() {
        let env = FakeEnvironment::linux().with_file("/etc/os-release", "ID=debian\n");
        assert_eq!(detect_package_family(&env), Some(PackageFamily::Apt));
    }

    #[test]
    fn unrecognized_distro_returns_none_not_a_guess() {
        let env =
            FakeEnvironment::linux().with_file("/etc/os-release", "NAME=\"Arch Linux\"\nID=arch\n");
        assert_eq!(detect_package_family(&env), None);
    }

    #[test]
    fn missing_os_release_returns_none() {
        let env = FakeEnvironment::linux();
        assert_eq!(detect_package_family(&env), None);
    }

    #[test]
    fn krun_runtime_has_no_apt_package_yet() {
        assert_eq!(package_for(CheckId::KrunRuntime, PackageFamily::Apt), None);
        assert_eq!(
            package_for(CheckId::KrunRuntime, PackageFamily::Dnf),
            Some("crun-krun")
        );
    }

    #[test]
    fn host_os_and_kvm_have_no_package_fix_on_any_family() {
        for family in [PackageFamily::Dnf, PackageFamily::Apt] {
            assert_eq!(package_for(CheckId::HostOs, family), None);
            assert_eq!(package_for(CheckId::Kvm, family), None);
        }
    }

    #[test]
    fn libkrunfw_has_a_dnf_package_name_but_no_confirmed_apt_package_yet() {
        assert_eq!(
            package_for(CheckId::Libkrunfw, PackageFamily::Dnf),
            Some("libkrunfw")
        );
        assert_eq!(package_for(CheckId::Libkrunfw, PackageFamily::Apt), None);
    }

    #[test]
    fn crun_version_has_a_dnf_package_name_but_no_confirmed_apt_package_yet() {
        assert_eq!(
            package_for(CheckId::CrunVersion, PackageFamily::Dnf),
            Some("crun-krun")
        );
        assert_eq!(package_for(CheckId::CrunVersion, PackageFamily::Apt), None);
    }

    #[test]
    fn passt_has_a_dnf_package_name_but_no_confirmed_apt_package_yet() {
        assert_eq!(
            package_for(CheckId::Passt, PackageFamily::Dnf),
            Some("passt")
        );
        assert_eq!(package_for(CheckId::Passt, PackageFamily::Apt), None);
    }

    #[test]
    fn crun_fallback_urls_are_dnf_installable_https_urls_for_a_matching_pair() {
        for url in [CRUN_FALLBACK_URL, CRUN_KRUN_FALLBACK_URL] {
            assert!(url.starts_with("https://"));
            assert!(url.ends_with(".rpm"));
        }
        // Same version number in both -- a mismatched crun/crun-krun pair
        // is exactly the failure mode this fallback exists to avoid.
        assert!(CRUN_FALLBACK_URL.contains("/1.29.1/"));
        assert!(CRUN_KRUN_FALLBACK_URL.contains("/1.29.1/"));
        assert_eq!(CRUN_PINNED_VERSION, (1, 29, 1));
    }

    #[test]
    fn install_command_accepts_multiple_packages_in_one_invocation() {
        let (program, args) = install_command(
            PackageFamily::Dnf,
            &["crun-1.29.1.rpm", "crun-krun-1.29.1.rpm"],
        );
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            vec![
                "dnf".to_string(),
                "install".to_string(),
                "-y".to_string(),
                "crun-1.29.1.rpm".to_string(),
                "crun-krun-1.29.1.rpm".to_string(),
            ]
        );
    }

    #[test]
    fn libkrunfw_fallback_url_is_a_dnf_installable_https_url() {
        assert!(LIBKRUNFW_FALLBACK_URL.starts_with("https://"));
        assert!(LIBKRUNFW_FALLBACK_URL.ends_with(".rpm"));
    }

    #[test]
    fn rpm_package_version_reports_the_parsed_version() {
        let env = FakeEnvironment::linux()
            .with_command_ok("rpm -q --queryformat %{VERSION}\\n crun-krun", "1.28\n");
        assert_eq!(rpm_package_version(&env, "crun-krun"), Some((1, 28, 0)));
    }

    #[test]
    fn rpm_package_version_is_none_when_the_package_is_not_installed() {
        let env = FakeEnvironment::linux();
        assert_eq!(rpm_package_version(&env, "crun-krun"), None);
    }

    #[test]
    fn parse_dotted_version_treats_missing_components_as_zero() {
        assert_eq!(parse_dotted_version("5.5.0\n"), Some((5, 5, 0)));
        assert_eq!(parse_dotted_version("1.28\n"), Some((1, 28, 0)));
        assert_eq!(parse_dotted_version("2\n"), Some((2, 0, 0)));
        assert_eq!(parse_dotted_version(""), None);
    }

    #[test]
    fn betterleaks_has_a_dnf_package_but_no_confirmed_apt_package_yet() {
        assert_eq!(
            package_for(CheckId::Betterleaks, PackageFamily::Dnf),
            Some("betterleaks")
        );
        assert_eq!(package_for(CheckId::Betterleaks, PackageFamily::Apt), None);
    }
}
