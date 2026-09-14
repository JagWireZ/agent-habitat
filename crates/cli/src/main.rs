//! `habitat` -- the operator-facing CLI entrypoint.
//!
//! Phase 1 wires up two subcommands against the Phase 0 skeleton:
//! - `habitat install` -- runs `habitat-install::run_install_checks`. If
//!   anything's missing, it offers to install it: on "yes", detects the
//!   host's dnf/apt package-manager family
//!   (`docs/decisions/0001-host-os-layer.md`'s 2026-09-14 amendment) and
//!   runs the actual `sudo <pkg-mgr> install` command for each fixable
//!   check, then re-verifies before reporting the final result.
//! - `habitat run` -- runs `habitat-install::run_preflight` and then stops;
//!   the rest of the session lifecycle (disk build, VM launch, prompt
//!   loop, teardown) is assembled in Phase 7 from Phases 2-6.
//!
//! No arg-parsing dependency is taken here: with no dependency-fetch
//! access in this environment (see Phase 1 implementation notes) and only
//! two subcommands and one flag (`--verbose`/`-v`) to recognize, hand-rolled
//! parsing is simpler and has fewer moving parts than pulling in a
//! framework for it.
//!
//! Default output is written for a general audience (think Docker
//! Desktop's or Homebrew's `doctor` output): a plain-English pass/fail
//! checklist first, then -- only if something's missing -- a separate
//! "here's what to do" section listing one concrete fix per failed item,
//! so the checklist itself stays scannable instead of interleaving status
//! and remediation prose line by line.
//! Internal component names (Podman, crun-krun, libkrun, ...) are reserved
//! for `--verbose`/`-v` -- shown as a dimmed line under each fix -- and for
//! the audit log, which always gets the full technical detail regardless
//! of this flag.

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
    }
}

/// A failed check's fix, split into a one-line "what/why" and, separately,
/// the exact commands to run -- so the two never run together mid-sentence
/// (naming the actual thing to install, e.g. "podman", since "install the
/// container runtime" is meaningless to someone who doesn't already know
/// that's what it means). Deeper internals (exact error text, PATH
/// resolution) still live in [`technical_detail`], shown only under
/// `--verbose`.
///
/// Not every check has a runnable command -- a BIOS setting or "there is
/// no fix" can't be copy-pasted into a terminal, so `commands` is empty
/// rather than faking one.
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
    }
}

/// The jargon-bearing detail for a failed check: the internal component
/// names, the exact error, and what to actually install/configure in
/// toolchain terms. Reserved for `--verbose` output and the audit log --
/// never shown by default (per the "no jargon in default output" rule).
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
    }
}

/// Prints one line per check in plain English -- just the status, nothing
/// else -- so the whole list stays scannable at a glance. `habitat
/// install` is still verify-only -- this only changes what's displayed,
/// not what's on the host -- so the checklist is safe to print even when
/// the run is ultimately going to fail.
///
/// Passes get a green check mark, failures a red X (colors auto-disabled
/// when stdout isn't a terminal, or `NO_COLOR` is set -- see `output.rs`).
/// What to do about a failure lives in [`print_required_steps`], printed
/// as its own section after the full list rather than interleaved here.
fn print_checklist(statuses: &[CheckStatus]) {
    let s = style();
    println!("{}", s.bold("Checking your system..."));
    for status in statuses {
        match &status.result {
            Ok(()) => println!(
                "  {} {:<26} Looks good",
                s.green_bold("\u{2714}"),
                friendly_name(status.check)
            ),
            Err(_) => println!(
                "  {} {:<26} {}",
                s.red_bold("\u{2718}"),
                friendly_name(status.check),
                friendly_status(status.check)
            ),
        }
    }
    println!();
}

/// Printed after the checklist, only when at least one check failed: one
/// numbered step per failed item, each in the same shape -- a bold
/// "Step X of N -- <name>" heading, a one-line reason, a blank line, then
/// the exact commands (if any) as a clearly offset, copy-pasteable block,
/// never embedded mid-sentence. The steps' failed checks don't depend on
/// each other today (each is a standalone binary/socket presence check),
/// so the section says so up front rather than implying a required order.
///
/// With `verbose`, each step also gets a dimmed line with the raw
/// technical error and the jargon-bearing fix -- the audit log always has
/// this detail regardless of the flag.
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

/// Checks with a real package-manager fix -- the only ones the
/// auto-install step ever offers to run something for. `HostOs` (no fix
/// on this host at all) and `Kvm` (a firmware setting, not a package) are
/// never included.
fn is_installable(check: CheckId) -> bool {
    matches!(check, CheckId::Podman | CheckId::KrunRuntime)
}

/// Reads a yes/no answer from stdin, defaulting to "no" on anything else
/// (including EOF/a piped-empty stdin) -- an ambiguous answer must never
/// be treated as consent to run `sudo` commands.
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

/// What happens once the operator has agreed to auto-install: either a
/// recognized package-manager family to actually run installs through, or
/// an explicit "nothing to run" -- decided once, up front, so `cmd_install`
/// is a straight match on this rather than interleaving detection with
/// the printing/execution that follows. Kept as its own function (over
/// `crates/install`'s own `Environment` seam) so this decision is
/// unit-testable without going through stdin/stdout at all.
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
                // Re-run the checks from scratch rather than trusting the
                // install commands' own exit codes -- the same fail-closed
                // posture as everything else in this crate.
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
            // The required-steps section below already says what to do
            // about each failure -- don't repeat it as a second,
            // error-shaped line; just close out and point at where the
            // full technical detail lives.
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
    let statuses = preflight_report(&env);
    print_checklist(&statuses);
    let s = style();
    match run_preflight(&env, &audit) {
        Ok(()) => {
            // Phase 1 stops here. Phases 2-6 (disk build, VM launch,
            // two-point sync, egress, full audit) are assembled behind
            // this point in Phase 7.
            eprintln!(
                "{}",
                s.green_bold(
                    "Everything looks good, but starting a session isn't supported yet (still being built)."
                )
            );
            ExitCode::FAILURE
        }
        Err(_) => {
            // Same reasoning as cmd_install: the required-steps section
            // below already says what to do about each failure.
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

/// Points at the audit log for full technical detail, phrased for a
/// reader who doesn't necessarily know what an audit log is. Nudges
/// towards `--verbose` unless the caller already used it.
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

    /// The fallback path (`§6` in `tmp/wip/phase-1-tasks.md`): a host whose
    /// package-manager family can't be recognized (or whose
    /// `/etc/os-release` is missing/unreadable) must resolve to
    /// `NoFamilyDetected` -- never a guessed family, and never `Run`, which
    /// is the only variant `cmd_install` will actually invoke
    /// `install_missing` for.
    #[test]
    fn unrecognized_distro_plans_no_auto_install() {
        let env = FakeEnvironment::linux()
            .with_file("/etc/os-release", "NAME=\"Arch Linux\"\nID=arch\n");
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

    /// The recognized-family counterpart, so this test only fails for the
    /// right reason (a real regression) rather than `AutoInstallPlan`
    /// always resolving to `NoFamilyDetected` regardless of input.
    #[test]
    fn recognized_distro_plans_to_run_on_its_family() {
        let env = FakeEnvironment::linux().with_file("/etc/os-release", "ID=ubuntu\n");
        assert!(matches!(
            plan_auto_install(&env),
            AutoInstallPlan::Run(PackageFamily::Apt)
        ));
    }
}
