//! `habitat` -- the operator-facing CLI entrypoint.
//!
//! Two subcommands:
//! - `habitat install` -- runs `habitat-install::run_install_checks`. If
//!   anything's missing, offers to install it: detects the host's dnf/apt
//!   package-manager family, runs `sudo <pkg-mgr> install` for each
//!   fixable check, then re-verifies before reporting the final result.
//! - `habitat run` -- runs `habitat-install::run_preflight` and stops; the
//!   rest of the session lifecycle is assembled elsewhere.
//!
//! No arg-parsing dependency: only two subcommands and one flag
//! (`--verbose`/`-v`), so hand-rolled parsing is simpler.
//!
//! Default output is a plain-English pass/fail checklist, then (only if
//! something's missing) a separate "here's what to do" section with one
//! concrete fix per failed item. Each checklist line carries the check's
//! short id (`CheckId::name()`) alongside the plain-English name, matching
//! the audit log and `--verbose` detail. Exact binaries/packages/error
//! text are reserved for `--verbose` and the audit log.

mod output;

use habitat_install::{
    detect_package_family, install_missing, install_report, preflight_report, run_install_checks,
    run_preflight, CheckId, CheckStatus, InstallAttempt, PackageFamily, SystemEnvironment,
};
use output::style;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
    match args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
    {
        Some("install") => cmd_install(verbose),
        Some("run") => cmd_run(verbose),
        Some(other) => {
            eprintln!("habitat: unknown subcommand '{other}' (expected 'install' or 'run')");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("habitat: expected a subcommand ('install' or 'run')");
            ExitCode::FAILURE
        }
    }
}

fn audit_sink() -> habitat_audit::FileAuditSink {
    habitat_audit::FileAuditSink::new(habitat_policy::default_audit_log_path())
}

/// Short, jargon-free banner printed before the checklist: what's being
/// checked and why, in the terms a non-expert would use, not the internal
/// component names (those live behind `--verbose` and in the audit log).
fn print_intro(heading: &str) {
    let s = style();
    println!("{}", s.bold(heading));
    println!("We're checking that your computer can run isolated sandboxes to keep each session separate and secure.");
    println!();
}

/// Plain-English display name for a check -- what a non-expert would call
/// the thing being verified, not its internal component name.
fn friendly_name(check: CheckId) -> &'static str {
    match check {
        CheckId::HostOs => "Operating system",
        CheckId::Kvm => "Hardware virtualization",
        CheckId::Podman => "Container runtime",
        CheckId::KrunRuntime => "Sandbox isolation layer",
        CheckId::CrunVersion => "VM networking support",
        CheckId::Passt => "Sandbox networking",
        CheckId::Libkrunfw => "Virtual machine kernel",
        CheckId::Betterleaks => "Content secrets scanner",
    }
}

/// Short plain-English status word for a failed check (paired with the
/// friendly fix suggestion right underneath it).
fn friendly_status(check: CheckId) -> &'static str {
    match check {
        CheckId::HostOs => "Not supported",
        CheckId::Kvm => "Not available",
        CheckId::Podman => "Not found",
        CheckId::KrunRuntime => "Not found",
        CheckId::CrunVersion => "Too old",
        CheckId::Passt => "Not found",
        CheckId::Libkrunfw => "Not found",
        CheckId::Betterleaks => "Not found",
    }
}

/// A failed check's fix: a one-line reason plus the exact commands to run.
/// `commands` is empty when there's nothing copy-pasteable (a BIOS
/// setting, or no fix at all). Deeper internals live in
/// [`technical_detail`], shown only under `--verbose`.
struct Fix {
    reason: &'static str,
    commands: &'static [&'static str],
}

fn fix_for(check: CheckId) -> Fix {
    match check {
        CheckId::HostOs => Fix {
            reason: "Agent Habitat only runs on Linux machines right now, so there isn't a fix available on this computer.",
            commands: &[],
        },
        CheckId::Kvm => Fix {
            reason: "Turn on virtualization support (VT-x on Intel, AMD-V on AMD) in your computer's BIOS/UEFI settings, then reboot -- this is a firmware setting, not something a command can turn on. If this is a cloud VM, ask your provider to enable nested virtualization instead. If /dev/kvm exists but this still fails, add your user to the kvm group and log back in.",
            commands: &["sudo usermod -aG kvm $USER   # then log out and back in"],
        },
        CheckId::Podman => Fix {
            reason: "Installs Podman, the rootless container/VM engine Agent Habitat launches sandboxes through -- no daemon or elevated privileges required. (`habitat install` can run this for you -- see the prompt above.)",
            commands: &[
                "sudo dnf install -y podman      # AlmaLinux/Fedora/RHEL-family",
                "sudo apt-get install -y podman  # Debian/Ubuntu-family",
            ],
        },
        CheckId::KrunRuntime => Fix {
            reason: "Installs crun-krun, the OCI runtime (backed by libkrun) Podman uses to launch each session in its own microVM instead of a shared-kernel container. Not yet packaged for Debian/Ubuntu-family hosts.",
            commands: &["sudo dnf install -y crun-krun   # AlmaLinux/Fedora/RHEL-family"],
        },
        CheckId::CrunVersion => Fix {
            reason: "This host's crun/krun build needs to be this project's own pinned, confirmed-good release for real sandboxed networking to actually work -- without it, a session can silently fall back to a networking mode this project doesn't restrict at all, or (a real Fedora finding) accept the right settings but still reset every guest connection. (`habitat install` can run this for you -- see the prompt above.) On every AlmaLinux/Fedora/RHEL-family host, when this check fails, `habitat install` installs this project's own pinned crun/crun-krun build directly, never the distro's own repo package. Not yet packaged for Debian/Ubuntu-family hosts.",
            commands: &["sudo dnf install -y crun-krun   # AlmaLinux/Fedora/RHEL-family; `habitat install` uses a pinned build instead of this"],
        },
        CheckId::Passt => Fix {
            reason: "Installs passt, the actual program that gives each sandboxed session its own real virtual network interface -- a separate requirement from the crun/krun build check above, which only confirms crun-krun is new enough to hand off to passt, not that passt is actually installed. (`habitat install` can run this for you -- see the prompt above.) Not yet packaged for Debian/Ubuntu-family hosts.",
            commands: &["sudo dnf install -y passt   # AlmaLinux/Fedora/RHEL-family"],
        },
        CheckId::Libkrunfw => Fix {
            reason: "Installs libkrunfw, the library bundling the actual guest kernel `krun` boots -- required for any session to launch even though `krun --version` alone doesn't check for it. (`habitat install` can run this for you -- see the prompt above.) On AlmaLinux/RHEL-family hosts, EPEL doesn't carry this package under any name; `habitat install` falls back to a direct Fedora build automatically when that happens. Not yet packaged for Debian/Ubuntu-family hosts.",
            commands: &["sudo dnf install -y libkrunfw   # AlmaLinux/Fedora/RHEL-family"],
        },
        CheckId::Betterleaks => Fix {
            reason: "Installs betterleaks, the content-based secrets scanner Agent Habitat runs against a project's files when that project's config has content scanning turned on (the default). (`habitat install` can run this for you -- see the prompt above.) Not yet packaged for Debian/Ubuntu-family hosts; on those, turn content scanning off in the project's config (secrets_scan.content: disabled) if that's a deliberate choice for this project.",
            commands: &["sudo dnf install -y betterleaks   # AlmaLinux/Fedora/RHEL-family, via EPEL"],
        },
    }
}

/// Jargon-bearing detail for a failed check. Reserved for `--verbose`
/// output and the audit log, never shown by default.
fn technical_detail(check: CheckId) -> &'static str {
    match check {
        CheckId::HostOs => {
            "Agent Habitat's isolation model (rootless Podman + the krun runtime, backed by libkrun) is Linux-only."
        }
        CheckId::Kvm => {
            "Enable VT-x/AMD-V virtualization extensions in firmware, confirm /dev/kvm is present, and add the current user to the `kvm` group (or otherwise grant it read+write on the device node) -- rootless launch needs no further elevation beyond that."
        }
        CheckId::Podman => {
            "Install podman and confirm it works rootless for this user (`podman info` succeeds without a daemon or elevated privileges)."
        }
        CheckId::KrunRuntime => {
            "Install the `crun-krun` package so `krun` (the OCI runtime binary Podman exec's, with libkrun linked directly into it -- note the package and binary are named differently) is resolvable on PATH -- there is no separate hypervisor binary to install alongside it."
        }
        CheckId::CrunVersion => {
            "Confirm `krun --version`'s reported crun version is >= checks::MIN_CRUN_VERSION_FOR_PASST -- this project's own pinned, confirmed-good crun-krun release (1.29.1), not merely crun 1.27.1 (the version that added the krun.use_passt OCI annotation). An older build than 1.27.1 silently falls back to libkrun's default TSI networking regardless of `--network pasta` (`tsi_hijack` on the guest's kernel command line, PF_TSI*/PF_TSIU registered, no virtio-net device at all), with no error pointing at the real cause. Passing that older, looser cutoff isn't sufficient on its own, though: real Fedora 44 hardware (2026-09-16) with a repo `crun-krun` reporting 1.28 passed a >=1.27.1 check and got a real passt-backed guest, but every SSH connection into it reset mid-handshake (a loopback packet capture showed the RST coming from pasta's own splice, never reaching the guest's sshd) -- which is why the cutoff was raised to the exact pinned build. When this check fails, `habitat install`'s auto-install step installs `package_manager::CRUN_FALLBACK_URL`/`CRUN_KRUN_FALLBACK_URL` (that same pinned, matching Fedora Koji build pair) directly, on AlmaLinux and Fedora alike, skipping the plain `dnf install crun-krun` step since a failing check already means the repo package can't be new enough. This check is deliberately separate from `CheckId::Passt` below: it only tests crun-krun's *ability* to hand off to passt, never whether passt itself is installed."
        }
        CheckId::Passt => {
            "Confirm `passt --version` runs successfully -- `passt` (and its `pasta` mode, the one crun-krun actually invokes per `docs/decisions/0004-networking-layer.md`) is the real userspace program that gives the guest its virtio-net device and translates its traffic; `checks::crun_version` passing says nothing about whether this package is actually present, only that crun-krun is new enough to use it if it is. Podman's own `--network pasta` driver only recommends this package on some distros rather than hard-requiring it, so a host can otherwise pass every check here and still fail to get a real network at session-launch time with no earlier warning. `habitat install`'s auto-install step installs the plain `passt` package on the Dnf family -- no pinned-build fallback, unlike crun-krun/libkrunfw, since there's no known version-specific bug behind it."
        }
        CheckId::Libkrunfw => {
            "Confirm `libkrunfw` resolves via `ldconfig -p` (not just that `krun --version` runs -- that path never dlopen's libkrunfw, so it passes even when this is missing entirely). Fedora's own `crun-krun`/`libkrun` packages pull in a matching `libkrunfw` automatically; EPEL's AlmaLinux/RHEL-family build of `libkrun` does not declare it as a dependency at all, and EPEL carries no `libkrunfw` package under any name regardless -- `habitat install`'s auto-install step falls back to `package_manager::LIBKRUNFW_FALLBACK_URL` (a pinned Fedora Koji build) on that family when the plain `dnf install libkrunfw` attempt fails."
        }
        CheckId::Betterleaks => {
            "Install the `betterleaks` binary (EPEL package `betterleaks` on the Dnf family; no confirmed Apt package yet) so it's resolvable on PATH, or set secrets_scan.content: disabled in the project's checked-in config. `habitat install` checks for it unconditionally (no project is in scope at install time), but it's only a hard `habitat run` preflight failure for a project that has content-based secrets scanning enabled (the default)."
        }
    }
}

/// Prints one line per check in plain English. Passes get a green check
/// mark, failures a red X. What to do about a failure lives in
/// [`print_required_steps`], printed as its own section afterward.
fn print_checklist(statuses: &[CheckStatus]) {
    let s = style();
    println!("{}", s.bold("Checking your system..."));
    for status in statuses {
        match &status.result {
            Ok(()) => println!(
                "  {} {:<14} {:<26} Looks good",
                s.green_bold("\u{2714}"),
                status.check.name(),
                friendly_name(status.check)
            ),
            Err(_) => println!(
                "  {} {:<14} {:<26} {}",
                s.red_bold("\u{2718}"),
                status.check.name(),
                friendly_name(status.check),
                friendly_status(status.check)
            ),
        }
    }
    println!();
}

/// Printed after the checklist, only when at least one check failed: one
/// numbered step per failed item -- a heading, a one-line reason, then any
/// commands as a copy-pasteable block. With `verbose`, each step also gets
/// a dimmed line with the raw technical error and jargon-bearing fix.
fn print_required_steps(statuses: &[CheckStatus], verbose: bool) {
    let s = style();
    let failed: Vec<_> = statuses
        .iter()
        .filter_map(|st| st.result.as_ref().err().map(|f| (st.check, f)))
        .collect();
    let total = failed.len();
    if total == 0 {
        return;
    }
    println!("{}", s.bold("Here's what to do:"));
    if total > 1 {
        println!("(These don't depend on each other -- do them in any order.)");
    }
    println!();
    for (i, (check, failure)) in failed.into_iter().enumerate() {
        let fix = fix_for(check);
        println!(
            "{}",
            s.bold(&format!(
                "Step {} of {total} \u{2014} {}",
                i + 1,
                friendly_name(check)
            ))
        );
        println!("{}", fix.reason);
        if !fix.commands.is_empty() {
            println!();
            for line in fix.commands {
                if line.is_empty() {
                    println!();
                } else {
                    println!("    {line}");
                }
            }
        }
        if verbose {
            println!();
            println!(
                "    {}",
                s.dim(&format!("technical detail: {}", failure.message))
            );
            println!(
                "    {}",
                s.dim(&format!("technical fix: {}", technical_detail(check)))
            );
        }
        println!();
    }
}

/// Checks with a real package-manager fix. `HostOs` (no fix at all) and
/// `Kvm` (a firmware setting) are never included.
fn is_installable(check: CheckId) -> bool {
    matches!(
        check,
        CheckId::Podman
            | CheckId::KrunRuntime
            | CheckId::CrunVersion
            | CheckId::Passt
            | CheckId::Libkrunfw
            | CheckId::Betterleaks
    )
}

/// Reads a yes/no answer from stdin, defaulting to "no" on anything else
/// (including EOF) -- an ambiguous answer must never be treated as
/// consent to run `sudo` commands.
fn prompt_yes_no(question: &str) -> bool {
    use std::io::Write;
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Prints the outcome of each auto-install attempt, in the same
/// plain-English register as [`print_checklist`].
fn print_install_attempts(attempts: &[InstallAttempt], s: output::Style) {
    for attempt in attempts {
        match attempt {
            InstallAttempt::Succeeded { check, package } => println!(
                "  {} Installed {package} ({})",
                s.green_bold("\u{2714}"),
                friendly_name(*check)
            ),
            InstallAttempt::Failed { check, package } => println!(
                "  {} Couldn't install {package} ({}) -- see the output above",
                s.red_bold("\u{2718}"),
                friendly_name(*check)
            ),
            InstallAttempt::NotAvailable { check } => println!(
                "  {} No automatic install is available yet for {} on this Linux distribution",
                s.dim("\u{2014}"),
                friendly_name(*check)
            ),
        }
    }
    println!();
}

/// What happens once the operator has agreed to auto-install: a
/// recognized package-manager family to run installs through, or an
/// explicit "nothing to run".
enum AutoInstallPlan {
    Run(PackageFamily),
    NoFamilyDetected,
}

fn plan_auto_install<E: habitat_install::Environment>(env: &E) -> AutoInstallPlan {
    match detect_package_family(env) {
        Some(family) => AutoInstallPlan::Run(family),
        None => AutoInstallPlan::NoFamilyDetected,
    }
}

fn cmd_install(verbose: bool) -> ExitCode {
    let env = SystemEnvironment;
    let audit = audit_sink();
    print_intro("Setting up Agent Habitat");
    let mut statuses = install_report(&env);
    print_checklist(&statuses);
    let s = style();

    let fixable_failed: Vec<CheckId> = statuses
        .iter()
        .filter(|st| !st.passed() && is_installable(st.check))
        .map(|st| st.check)
        .collect();

    if !fixable_failed.is_empty()
        && prompt_yes_no("Would you like Agent Habitat to install the missing pieces now? This runs `sudo` commands.")
    {
        println!();
        match plan_auto_install(&env) {
            AutoInstallPlan::Run(family) => {
                let attempts = install_missing(&env, &audit, family, &fixable_failed);
                print_install_attempts(&attempts, s);
                // Re-verify rather than trust the install commands' exit codes.
                statuses = install_report(&env);
                print_checklist(&statuses);
            }
            AutoInstallPlan::NoFamilyDetected => {
                println!(
                    "{}",
                    s.dim("Couldn't automatically recognize this Linux distribution's package manager -- install the missing pieces manually (see below).")
                );
                println!();
            }
        }
    }

    match run_install_checks(&env, &audit) {
        Ok(()) => {
            println!(
                "{}",
                s.green_bold("All set! Everything Agent Habitat needs is installed.")
            );
            ExitCode::SUCCESS
        }
        Err(_) => {
            print_required_steps(&statuses, verbose);
            eprintln!(
                "{}",
                s.red_bold("Setup isn't finished yet -- a couple of things need to be installed first (see above).")
            );
            print_detail_pointer(&s, &audit, verbose);
            ExitCode::FAILURE
        }
    }
}

fn cmd_run(verbose: bool) -> ExitCode {
    let env = SystemEnvironment;
    let audit = audit_sink();
    print_intro("Getting your session ready");
    // A missing `sandbox.yaml` in the current directory resolves to
    // `ProjectConfig::default()` (`habitat_policy::config::load`).
    let secrets_scan_content_enabled =
        habitat_policy::config::load(std::path::Path::new("sandbox.yaml"))
            .map(|c| c.secrets_scan.content.is_enabled())
            .unwrap_or(true);
    let statuses = preflight_report(&env, secrets_scan_content_enabled);
    print_checklist(&statuses);
    let s = style();
    match run_preflight(&env, &audit, secrets_scan_content_enabled) {
        Ok(()) => {
            eprintln!(
                "{}",
                s.green_bold(
                    "Everything looks good, but starting a session isn't supported yet (still being built)."
                )
            );
            ExitCode::FAILURE
        }
        Err(_) => {
            print_required_steps(&statuses, verbose);
            eprintln!(
                "{}",
                s.red_bold("Your session can't start yet -- a couple of things need to be installed first (see above).")
            );
            print_detail_pointer(&s, &audit, verbose);
            ExitCode::FAILURE
        }
    }
}

/// Points at the audit log for full technical detail; nudges towards
/// `--verbose` unless the caller already used it.
fn print_detail_pointer(s: &output::Style, audit: &habitat_audit::FileAuditSink, verbose: bool) {
    eprintln!(
        "{}",
        s.dim(&format!(
            "For full technical details, see the log at {}",
            audit.path().display()
        ))
    );
    if !verbose {
        eprintln!(
            "{}",
            s.dim("(Run with --verbose to see the technical details here instead.)")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use habitat_install::testing::FakeEnvironment;

    /// An unrecognized package-manager family must resolve to
    /// `NoFamilyDetected`, never a guessed family.
    #[test]
    fn unrecognized_distro_plans_no_auto_install() {
        let env =
            FakeEnvironment::linux().with_file("/etc/os-release", "NAME=\"Arch Linux\"\nID=arch\n");
        assert!(matches!(
            plan_auto_install(&env),
            AutoInstallPlan::NoFamilyDetected
        ));
    }

    #[test]
    fn missing_os_release_plans_no_auto_install() {
        let env = FakeEnvironment::linux();
        assert!(matches!(
            plan_auto_install(&env),
            AutoInstallPlan::NoFamilyDetected
        ));
    }

    #[test]
    fn recognized_distro_plans_to_run_on_its_family() {
        let env = FakeEnvironment::linux().with_file("/etc/os-release", "ID=ubuntu\n");
        assert!(matches!(
            plan_auto_install(&env),
            AutoInstallPlan::Run(PackageFamily::Apt)
        ));
    }
}
