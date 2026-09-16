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
        // `crun-krun` under its plain repo name -- kept here for
        // `KrunRuntime`'s own use (installing *some* `crun-krun` so `krun`
        // resolves on PATH at all) and for display/testing purposes, but
        // `installer::attempt_one` no longer calls this for
        // `CheckId::CrunVersion` on the Dnf family: every Dnf-family host
        // now always installs the pinned `CRUN_FALLBACK_URL`/
        // `CRUN_KRUN_FALLBACK_URL` pair directly instead, never `dnf
        // install crun-krun` -- confirmed on real Fedora 44 hardware that
        // a repo build passing `checks::crun_version`'s version-number
        // gate can still ship a real `krun.use_passt` networking bug the
        // pinned build doesn't have (see `attempt_one`'s doc comment).
        (CheckId::CrunVersion, PackageFamily::Dnf) => Some("crun-krun"),
        (CheckId::CrunVersion, PackageFamily::Apt) => None,
        // `passt` under its own upstream/distro package name -- no known
        // version-specific bug behind it (unlike `crun-krun` above), so
        // this is the plain, only install path: no pinned-build fallback.
        // Not yet confirmed packaged for Debian/Ubuntu-family hosts
        // (this crate's whole `install`/`preflight` chain is v1-scoped to
        // AlmaLinux/Fedora/RHEL-family regardless, `docs/decisions/
        // 0001-host-os-layer.md`'s 2026-09-14 amendment).
        (CheckId::Passt, PackageFamily::Dnf) => Some("passt"),
        (CheckId::Passt, PackageFamily::Apt) => None,
        // `libkrunfw` under its own upstream package name -- kept here for
        // display/testing purposes, but `installer::attempt_one` no longer
        // calls this for the Dnf family: every Dnf-family host now always
        // installs `LIBKRUNFW_FALLBACK_URL` directly instead of `dnf
        // install libkrunfw`, for the same reason as `CrunVersion` above.
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

/// A pinned, real-hardware-confirmed source for `libkrunfw`, installed
/// unconditionally on every Dnf-family host (`installer::attempt_one`) --
/// not only AlmaLinux/RHEL-family, where EPEL carries no `libkrunfw`
/// package under any name at all (confirmed: `dnf install libkrunfw`
/// there returns "No match for argument"). Also used on Fedora, whose own
/// repo build otherwise resolves fine but isn't trusted for this
/// specifically enough (see `CRUN_FALLBACK_URL`'s doc comment for why
/// "resolves fine" isn't the same guarantee as "works correctly").
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

/// Pinned Koji URLs for `crun` + `crun-krun` together, installed
/// unconditionally on every Dnf-family host (`installer::attempt_one`),
/// never `dnf install crun-krun`. Both packages must be installed in the
/// same `dnf install` invocation: `crun-krun` needs the exact matching
/// `crun` version, and installing them separately risks leaving a
/// mismatched pair (`installer::run_package_command` always passes both
/// together, never one at a time).
///
/// Originally only a fallback for hosts whose repo `crun-krun` was too
/// old for the `krun.use_passt` OCI annotation (`checks::crun_version`,
/// `checks::MIN_CRUN_VERSION_FOR_PASST`) -- AlmaLinux 10's AppStream
/// package (`crun-krun-1.27-2.el10_2`) is one patch release behind the
/// 1.27.1 cutoff. Confirmed end-to-end on real AlmaLinux 10.2 hardware
/// (`tmp/wip/egress-validation`): installs cleanly, `crun --version`
/// reports 1.29.1 afterward, and a real `--annotation krun.use_passt=1`
/// session actually gets `passt`-backed networking (no more
/// `tsi_hijack`).
///
/// Now installed on every Dnf-family host regardless of the repo's own
/// version, including genuine Fedora: confirmed on real Fedora 44
/// hardware (2026-09-16, `tmp/wip/vm-launch-validation`) that Fedora's
/// own repo `crun-krun` (1.28) passes the version-number gate and boots a
/// real `passt`-backed guest, but every SSH connection into it reset
/// mid-handshake -- a packet capture on the loopback forward showed the
/// RST coming from `pasta`'s own splice, before the guest's sshd ever saw
/// the connection. This pinned 1.29.1 build does not have that problem.
/// "New enough per the version check" turned out not to mean "free of
/// this bug," so the fallback is no longer conditional on the check
/// failing -- see `installer::attempt_one`'s doc comment.
///
/// **This will eventually go stale**, same as `LIBKRUNFW_FALLBACK_URL` --
/// see that constant's doc comment for what to do when `habitat install`
/// starts reporting this fallback as `Failed`.
pub const CRUN_FALLBACK_URL: &str =
    "https://kojipkgs.fedoraproject.org/packages/crun/1.29.1/1.fc43/x86_64/crun-1.29.1-1.fc43.x86_64.rpm";
pub const CRUN_KRUN_FALLBACK_URL: &str =
    "https://kojipkgs.fedoraproject.org/packages/crun/1.29.1/1.fc43/x86_64/crun-krun-1.29.1-1.fc43.x86_64.rpm";

/// The exact version [`CRUN_FALLBACK_URL`]/[`CRUN_KRUN_FALLBACK_URL`]
/// install -- kept in sync with those URLs by
/// `crun_fallback_urls_are_dnf_installable_https_urls_for_a_matching_pair`
/// below. `installer::attempt_one` compares a host's
/// [`rpm_package_version`] of `crun-krun` against this before running the
/// pinned install, so a host that's already at this version or newer
/// (a future Fedora repo build, or an operator's own manual install)
/// never gets downgraded by it.
pub const CRUN_PINNED_VERSION: (u32, u32, u32) = (1, 29, 1);

/// The installed version of `package` per `rpm`'s own query database --
/// `None` if it isn't installed at all, `rpm` itself isn't on PATH, or
/// the version string doesn't parse. Dnf-family only: there's no `rpm`
/// binary to ask on any other family, and callers must never invoke this
/// off it.
///
/// This is the one authoritative "what's actually installed" answer for
/// this family -- more direct than re-deriving it from a binary's own
/// `--version` banner (`krun --version`, e.g.), which is one more hop
/// removed from what the package manager itself has on record, and
/// doesn't exist at all for a library like `libkrunfw` that has no
/// executable of its own to ask (unused for it now, but kept general).
/// `installer::attempt_one` uses this to decide whether its pinned
/// `crun-krun` fallback build ([`CRUN_PINNED_VERSION`]) would actually
/// be a downgrade, never installing over a host that's already at or
/// past it.
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
/// as `0` -- rpm's own `%{VERSION}` field is just the dotted number, with
/// none of `crun --version`'s `"crun version "` prefix to strip first.
fn parse_dotted_version(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.lines().next()?.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

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
        // Kept in sync with CRUN_PINNED_VERSION by hand -- both URLs and
        // this tuple must describe the exact same release.
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
        // `rpm -q` on a missing package exits non-zero rather than
        // printing an empty version -- FakeEnvironment's default for an
        // unconfigured command is exactly that "not found" shape.
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
