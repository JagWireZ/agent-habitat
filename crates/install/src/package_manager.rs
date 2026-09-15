//! Host package-manager family detection, used only to pick the right
//! remediation command for `habitat install`'s optional auto-install step
//! (`installer.rs`) once a check has already failed. This never
//! influences whether a check passes or fails -- `checks.rs` stays
//! exactly as it was -- it only decides how the auto-install step talks
//! to the package manager, if the operator asks it to.
//!
//! Scope note (`docs/decisions/0001-host-os-layer.md`'s 2026-09-14
//! amendment): detecting the package-manager family is not the same as
//! claiming full end-to-end validation on that family -- v1 sign-off
//! still runs against AlmaLinux alone. This module only lets `habitat
//! install` offer a real install command on Fedora/RHEL-family and
//! Debian/Ubuntu-family hosts instead of silently doing nothing there.

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
/// classify (file missing, or an `ID`/`ID_LIKE` this doesn't recognize)
/// -- callers must treat that as "no auto-install available here," never
/// guess a default family.
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
/// there's no package-manager fix at all on this host (`HostOs`/`Kvm`: a
/// package manager can't fix a firmware setting or an unsupported OS) or
/// the package doesn't exist for this family yet (`KrunRuntime` on `Apt`:
/// `crun-krun` has no `.deb` until Ubuntu's own v2 roadmap stage --
/// `docs/decisions/0006-distribution-packaging-layer.md`).
pub fn package_for(check: CheckId, family: PackageFamily) -> Option<&'static str> {
    match (check, family) {
        (CheckId::Podman, PackageFamily::Dnf) => Some("podman"),
        (CheckId::Podman, PackageFamily::Apt) => Some("podman"),
        (CheckId::KrunRuntime, PackageFamily::Dnf) => Some("crun-krun"),
        (CheckId::KrunRuntime, PackageFamily::Apt) => None,
        // `crun-krun` again, by the same name -- the primary attempt for
        // the version check. On a genuine Fedora host this is enough by
        // itself (Fedora's own repos already carry a new-enough build);
        // `installer.rs` falls back to CRUN_FALLBACK_URL/
        // CRUN_KRUN_FALLBACK_URL when the check still fails afterward,
        // which is what actually happens on AlmaLinux 10 today -- its
        // AppStream `crun-krun-1.27-2.el10_2` is already the newest
        // version that repo carries, so re-running `dnf install crun-krun`
        // against an already-installed package is a same-version no-op,
        // not a fix (see `installer.rs::attempt_one`'s re-verification
        // step, which exists specifically because this case can't be told
        // apart from a real fix by the install command's exit code alone).
        (CheckId::CrunVersion, PackageFamily::Dnf) => Some("crun-krun"),
        (CheckId::CrunVersion, PackageFamily::Apt) => None,
        // `libkrunfw` under its own upstream package name -- the primary
        // attempt. On a genuine Fedora host this check never even gets
        // this far: installing `crun-krun` there already pulls in a
        // matching `libkrunfw` automatically, so `checks::libkrunfw`
        // already passes and `installer::install_missing` never attempts
        // anything for this check at all. This mapping exists for hosts
        // where a `libkrunfw` package genuinely is resolvable by name but
        // just hadn't been installed yet -- `installer.rs` falls back to
        // `LIBKRUNFW_FALLBACK_URL` if this attempt itself fails, which is
        // what actually happens on AlmaLinux 10 today (no `libkrunfw`
        // package under any name in EPEL -- confirmed real-hardware,
        // `tmp/wip/vm-launch-validation`).
        (CheckId::Libkrunfw, PackageFamily::Dnf) => Some("libkrunfw"),
        (CheckId::Libkrunfw, PackageFamily::Apt) => None,
        (CheckId::HostOs, _) | (CheckId::Kvm, _) => None,
        // `betterleaks` is EPEL-distributed under its own upstream name
        // (`betterleaks`) on the Fedora/RHEL-family branch -- AlmaLinux
        // rebuilds EPEL's SRPMs for EL10, so the same package name
        // resolves there once EPEL is enabled. No confirmed `.deb` exists
        // for Debian/Ubuntu-family hosts yet, so that side stays `None`
        // (same "None, never a guess" posture as the unrecognized-distro
        // case above) rather than guessing a name.
        (CheckId::Betterleaks, PackageFamily::Dnf) => Some("betterleaks"),
        (CheckId::Betterleaks, PackageFamily::Apt) => None,
    }
}

/// A pinned, real-hardware-confirmed fallback source for `libkrunfw` on
/// the Dnf family, used only when the primary `package_for` attempt
/// (`dnf install libkrunfw`) itself fails -- which is exactly what
/// happens on AlmaLinux 10 today, since EPEL carries no `libkrunfw`
/// package under any name (confirmed: `dnf install libkrunfw` there
/// returns "No match for argument", not a version conflict).
///
/// This is a direct Koji (Fedora's own build system) URL for a Fedora 43
/// x86_64 build of upstream `libkrunfw` v5.5.0, `dnf install`-able
/// directly by URL. Confirmed end-to-end on real AlmaLinux 10.2 hardware
/// (`tmp/wip/vm-launch-validation`): installs cleanly, resolves via
/// `ldconfig -p` as `libkrunfw.so.5` (the exact SONAME the EPEL
/// `libkrun-1.17.4` build needs), and a real `krun`-backed `podman run`
/// boots successfully afterward. `libkrunfw` is close to a self-contained
/// blob (it bundles a prebuilt Linux kernel behind a thin C shim), which
/// is why a Fedora-built binary works on a RHEL-family host at all here --
/// this is still a cross-distro binary, not an officially supported
/// combination, and is a stopgap for exactly this gap, not a permanent
/// answer.
///
/// **This will eventually go stale.** Fedora rotates old builds out of
/// active Koji retention over time, and a newer `libkrun` build may need
/// a newer `libkrunfw` SONAME than this one provides. If `habitat
/// install` starts reporting this fallback as `Failed`, check
/// <https://koji.fedoraproject.org/koji/packageinfo?packageID=35681> for
/// a current Fedora 43 (or the then-current stable release) x86_64 build
/// and update this constant -- and check whether EPEL or AlmaLinux itself
/// has shipped a real `libkrunfw` package in the meantime, which would
/// let this whole fallback (and this doc comment) be deleted.
pub const LIBKRUNFW_FALLBACK_URL: &str =
    "https://kojipkgs.fedoraproject.org/packages/libkrunfw/5.5.0/1.fc43/x86_64/libkrunfw-5.5.0-1.fc43.x86_64.rpm";

/// Pinned Koji URLs for `crun` + `crun-krun` together -- the fallback
/// when the installed `crun-krun` is too old to support the
/// `krun.use_passt` OCI annotation (`checks::crun_version`,
/// `checks::MIN_CRUN_VERSION_FOR_PASST`). Both packages must be installed
/// in the same `dnf install` invocation: `crun-krun` needs the exact
/// matching `crun` version, and installing them separately risks leaving
/// a mismatched pair (`installer::run_package_command` always passes both
/// together, never one at a time).
///
/// Same real-hardware-confirmed status and caveats as
/// [`LIBKRUNFW_FALLBACK_URL`]: a Fedora 43 binary running on a
/// RHEL-family host, not an officially supported combination, but the
/// only practical unblock while AlmaLinux's own AppStream package stays
/// at `crun-krun-1.27-2.el10_2` (one patch release behind the 1.27.1
/// cutoff). Confirmed end-to-end on real AlmaLinux 10.2 hardware
/// (`tmp/wip/egress-validation`): installs cleanly, `crun --version`
/// reports 1.29.1 afterward, and a real `--annotation krun.use_passt=1`
/// session actually gets `passt`-backed networking (no more
/// `tsi_hijack`).
///
/// **This will eventually go stale**, same as `LIBKRUNFW_FALLBACK_URL` --
/// see that constant's doc comment for what to do when `habitat install`
/// starts reporting this fallback as `Failed`.
pub const CRUN_FALLBACK_URL: &str =
    "https://kojipkgs.fedoraproject.org/packages/crun/1.29.1/1.fc43/x86_64/crun-1.29.1-1.fc43.x86_64.rpm";
pub const CRUN_KRUN_FALLBACK_URL: &str =
    "https://kojipkgs.fedoraproject.org/packages/crun/1.29.1/1.fc43/x86_64/crun-krun-1.29.1-1.fc43.x86_64.rpm";

/// The command (program + args) that installs `packages` as root on
/// `family`, all in one invocation -- `crun`+`crun-krun`'s fallback needs
/// both installed together so they stay a matching pair (see
/// `CRUN_FALLBACK_URL`'s doc comment); every other caller just passes a
/// single-element slice. Always non-interactive on the package manager's
/// own prompts (`-y`) -- `habitat install` already got the operator's
/// confirmation before calling this; `sudo` still prompts for a password
/// itself, which is why this runs through `Environment::
/// run_command_inherited` rather than the captured `run_command`.
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
    fn crun_fallback_urls_are_dnf_installable_https_urls_for_a_matching_pair() {
        for url in [CRUN_FALLBACK_URL, CRUN_KRUN_FALLBACK_URL] {
            assert!(url.starts_with("https://"));
            assert!(url.ends_with(".rpm"));
        }
        // Same version number in both -- a mismatched crun/crun-krun pair
        // is exactly the failure mode this fallback exists to avoid.
        assert!(CRUN_FALLBACK_URL.contains("/1.29.1/"));
        assert!(CRUN_KRUN_FALLBACK_URL.contains("/1.29.1/"));
    }

    #[test]
    fn install_command_accepts_multiple_packages_in_one_invocation() {
        let (program, args) =
            install_command(PackageFamily::Dnf, &["crun-1.29.1.rpm", "crun-krun-1.29.1.rpm"]);
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
    fn betterleaks_has_a_dnf_package_but_no_confirmed_apt_package_yet() {
        assert_eq!(
            package_for(CheckId::Betterleaks, PackageFamily::Dnf),
            Some("betterleaks")
        );
        assert_eq!(package_for(CheckId::Betterleaks, PackageFamily::Apt), None);
    }
}
