//! `habitat` -- the operator-facing CLI entrypoint.
//!
//! Two subcommands:
//! - `habitat install` -- runs `habitat-install::run_install_checks`. If
//!   anything's missing, offers to install it: detects the host's dnf/apt
//!   package-manager family, runs `sudo <pkg-mgr> install` for each
//!   fixable check, then re-verifies before reporting the final result.
//! - `habitat run --config <path> -- <agent> [agent-args...]` -- runs
//!   preflight, then assembles the full session lifecycle from
//!   `habitat_cli::run` (Phase 7): disk build, VM launch, a prompt loop
//!   with two-point sync, and teardown.
//!
//! No arg-parsing dependency: only two subcommands and a handful of flags,
//! so hand-rolled parsing (`habitat_cli::run::parse_run_args`) is simpler.
//!
//! Default output is a plain-English pass/fail checklist, then (only if
//! something's missing) a separate "here's what to do" section with one
//! concrete fix per failed item. Each checklist line carries the check's
//! short id (`CheckId::name()`) alongside the plain-English name, matching
//! the audit log and `--verbose` detail. Exact binaries/packages/error
//! text are reserved for `--verbose` and the audit log.

use habitat_cli::{output, run};
use habitat_install::{
    detect_package_family, install_missing, install_report, preflight_report, run_install_checks,
    run_preflight, CheckId, CheckStatus, InstallAttempt, PackageFamily, SystemEnvironment,
};
use output::style;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
    let subcommand = args.iter().position(|a| !a.starts_with('-'));
    match subcommand.map(|i| (args[i].as_str(), i)) {
        Some(("install", i)) if wants_help(&args[i + 1..]) => {
            print!("{}", install_help());
            ExitCode::SUCCESS
        }
        Some(("install", _)) => cmd_install(verbose),
        Some(("run", i)) if wants_help(&args[i + 1..]) => {
            print!("{}", run_help());
            ExitCode::SUCCESS
        }
        Some(("run", i)) => cmd_run(verbose, &args[i + 1..]),
        Some(("help", _)) => {
            print!("{}", top_level_help());
            ExitCode::SUCCESS
        }
        Some((other, _)) => {
            eprintln!("habitat: unknown subcommand '{other}' (expected 'install' or 'run')");
            eprintln!("Run `habitat --help` for usage.");
            ExitCode::FAILURE
        }
        None if wants_help(&args) => {
            print!("{}", top_level_help());
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("habitat: expected a subcommand ('install' or 'run')");
            eprintln!("Run `habitat --help` for usage.");
            ExitCode::FAILURE
        }
    }
}

/// True if `--help`/`-h` appears anywhere in `args`. Checked ahead of a
/// subcommand's own argument parsing so `habitat run --help` (which has
/// no `--` separator or agent command) prints help instead of a parse
/// error.
fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h")
}

fn top_level_help() -> String {
    "habitat -- give an AI coding agent its own disposable, sandboxed copy of your \
project to work in.\n\
\n\
Each `habitat run` session builds a fresh sandbox workspace from your project, \
launches it in an isolated VM, runs the agent you name against your prompts, and \
syncs its changes back out as a normal patch -- your real files are never touched \
directly. Network access from inside the sandbox is restricted to an allowlist, and \
secrets are filtered out before they ever reach it. Every check and session is \
logged.\n\
\n\
USAGE:\n\
    habitat <SUBCOMMAND> [OPTIONS]\n\
\n\
SUBCOMMANDS:\n\
    install    Check (and optionally install) what this machine needs to run sandboxes\n\
    run        Run an agent inside a disposable sandbox of the current project\n\
\n\
OPTIONS:\n\
    -v, --verbose    Show technical detail alongside the plain-English output\n\
    -h, --help       Print this help (or `habitat <SUBCOMMAND> --help` for subcommand help)\n\
\n\
EXAMPLES:\n\
    habitat install\n\
    habitat run\n\
    habitat run claude\n\
    habitat run --config sandbox.yaml codex --print\n"
        .to_string()
}

fn install_help() -> String {
    "habitat install -- check this machine's readiness to run Agent Habitat sandboxes.\n\
\n\
Verifies the operating system, hardware virtualization (KVM), rootless Podman, the \
crun-krun/libkrun sandbox runtime, passt networking, the libkrunfw guest kernel, and \
(if this project's config enables it) the betterleaks secrets scanner. Prints a \
pass/fail checklist; if anything's missing, offers to install it via this system's \
package manager (dnf on AlmaLinux/Fedora/RHEL-family, apt on Debian/Ubuntu-family) \
and re-verifies before reporting the final result.\n\
\n\
USAGE:\n\
    habitat install [OPTIONS]\n\
\n\
OPTIONS:\n\
    -v, --verbose    Show the technical reason and fix for each failed check\n\
    -h, --help       Print this help\n"
        .to_string()
}

fn run_help() -> String {
    "habitat run -- run an agent (or a shell) inside a disposable sandbox of the current \
project.\n\
\n\
Runs preflight checks, builds a disposable copy of the current project onto a \
sandbox disk, and launches it in an isolated VM. With no agent named, drops you into \
an interactive shell inside the sandbox -- your changes sync in before the shell \
opens, periodically while it's open, and once more when you exit it. With an agent \
named, reads prompts from stdin one at a time instead: each prompt is synced into the \
sandbox, run through the named agent once, and its results synced back out to your \
real project as a patch. Type 'exit' or 'quit' (or send EOF) to end a prompt session, \
or exit the shell to end a shell session -- the sandbox, its egress firewall, and the \
VM are torn down automatically either way.\n\
\n\
USAGE:\n\
    habitat run [--config <path>] [-v|--verbose] [<agent> [agent-args...]]\n\
\n\
<agent> is one of: claude, codex, opencode -- or `-- <command> [args...]` to run any \
other agent binary that supports a one-shot, single-prompt invocation mode. Omit it \
entirely for an interactive shell.\n\
\n\
OPTIONS:\n\
    --config <path>   Path to the project's config file (default: sandbox.yaml)\n\
    -v, --verbose     Show technical detail alongside the plain-English output\n\
    -h, --help        Print this help\n\
\n\
EXAMPLES:\n\
    habitat run\n\
    habitat run claude\n\
    habitat run --config sandbox.yaml codex --print\n\
    habitat run -- my-custom-agent --print\n"
        .to_string()
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

/// Guest image every session launches against -- a fixed Alpine image,
/// independent of the host roadmap (`docs/decisions/0002-guest-os-layer.md`).
const GUEST_IMAGE: &str = "localhost/habitat-guest:alpine";

/// This session's local egress proxy/DNS-forwarder address. Fixed rather
/// than an ephemeral port: the firewall ruleset applied at launch time
/// needs to know it in advance, and `crate::run::start_egress`'s
/// `TcpListener::bind` has to agree with it. Matches
/// `tests/manual/validate-egress.sh`'s own `PROXY_ADDR`.
///
/// **Known open item, not solved here:** the DNS forwarder half needs
/// port 53, a privileged port under Linux's default
/// `net.ipv4.ip_unprivileged_port_start` -- the same assumption
/// `validate-egress.sh` already makes and has not yet confirmed against
/// a hardened default sysctl. Not new to Phase 7.
const EGRESS_PROXY_ADDR: &str = "127.0.0.1:8443";

fn cmd_run(verbose: bool, rest: &[String]) -> ExitCode {
    let s = style();
    let run_args = match run::parse_run_args(rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("habitat run: {e}");
            return ExitCode::FAILURE;
        }
    };

    let config = match habitat_policy::config::load(&run_args.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "habitat run: could not load {}: {e}",
                run_args.config_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let raw_audit = audit_sink();
    let audit = habitat_audit::FilteringAuditSink::new(&raw_audit, config.audit.is_enabled());

    print_intro("Getting your session ready");
    let env = SystemEnvironment;
    let secrets_scan_content_enabled = config.secrets_scan.content.is_enabled();
    let statuses = preflight_report(&env, secrets_scan_content_enabled);
    print_checklist(&statuses);

    if run_preflight(&env, &audit, secrets_scan_content_enabled).is_err() {
        print_required_steps(&statuses, verbose);
        eprintln!(
            "{}",
            s.red_bold("Your session can't start yet -- a couple of things need to be installed first (see above).")
        );
        print_detail_pointer(&s, &raw_audit, verbose);
        return ExitCode::FAILURE;
    }

    let project_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("habitat run: could not read the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let state_dir = std::env::temp_dir().join(format!("habitat-session-{}", std::process::id()));
    let paths = run::SessionPaths::new(&state_dir);

    let vm_runner = habitat_vm::command_runner::SystemCommandRunner;
    let ws_runner = habitat_workspace::command_runner::SystemCommandRunner;
    let proxy_addr: std::net::SocketAddr = EGRESS_PROXY_ADDR.parse().expect("valid fixed address");

    // Egress (proxy + DNS forwarder) is boundary infrastructure for the
    // whole session, started once here -- not per-prompt -- and left to
    // be reclaimed by process exit; see `docs/decisions/
    // 0009-run-driver-prompt-loop.md` for why no graceful shutdown is
    // attempted for these threads specifically.
    let egress_audit = habitat_audit::FilteringAuditSink::new(
        habitat_audit::FileAuditSink::new(raw_audit.path()),
        config.audit.is_enabled(),
    );
    run::start_egress(
        proxy_addr,
        run::effective_egress_allowlist(&config),
        std::sync::Arc::new(egress_audit),
    );

    let build_request = run::build_request(&project_root, &paths, &config);
    if let Err(e) = habitat_workspace::pipeline::build(build_request, &ws_runner) {
        eprintln!("habitat run: disk build failed: {e}");
        print_detail_pointer(&s, &raw_audit, verbose);
        return ExitCode::FAILURE;
    }

    let keypair =
        match habitat_vm::guest_ssh::generate(&paths.guest_ssh_key_path(), &vm_runner) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("habitat run: could not generate session SSH key: {e}");
                return ExitCode::FAILURE;
            }
        };
    let session_id = habitat_vm::session::SessionId::generate();
    let launch_req = run::launch_request(
        session_id.clone(),
        &paths,
        &config,
        GUEST_IMAGE.to_string(),
        proxy_addr,
        keypair.public_key,
        keypair.private_key_path.clone(),
    );

    let launched = match habitat_vm::launcher::launch(&launch_req, &vm_runner, &audit) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("habitat run: VM launch failed: {e}");
            print_detail_pointer(&s, &raw_audit, verbose);
            return ExitCode::FAILURE;
        }
    };

    // Best-current-understanding, real-hardware-unconfirmed step -- see
    // `run::apply_egress_firewall_in_container`'s own doc comment.
    if let Err(e) =
        run::apply_egress_firewall_in_container(&vm_runner, session_id.as_str(), proxy_addr)
    {
        eprintln!("habitat run: could not apply the session's egress firewall rules: {e}");
        let _ = habitat_vm::launcher::teardown(&launched, &vm_runner, &audit);
        return ExitCode::FAILURE;
    }

    let patterns = if config.secrets_scan.filenames.is_enabled() {
        habitat_policy::blocklist::effective_patterns(&config.blocklist_additions)
    } else {
        Vec::new()
    };
    let guest = habitat_workspace::guest_exec::GuestEndpoint {
        host: &launched.guest_ssh_host,
        port: launched.guest_ssh_port,
        private_key_path: &launched.guest_ssh_private_key_path,
    };

    let session_result: Result<(), run::RunError> = match &run_args.mode {
        run::RunMode::Shell => {
            println!(
                "{}",
                s.green_bold("Session ready. Opening a shell in your sandbox -- exit it to end the session.")
            );
            run::run_shell_session(
                &project_root,
                &paths,
                guest,
                &patterns,
                &ws_runner,
                &audit,
            )
            .map(|_| ())
        }
        run::RunMode::Agent(agent) => {
            println!(
                "{}",
                s.green_bold("Session ready. Type a prompt and press enter (or 'exit' to end the session).")
            );
            let prompts = std::io::stdin().lines().map_while(Result::ok);
            run::run_prompt_loop(
                &project_root,
                &paths,
                guest,
                &patterns,
                agent,
                &ws_runner,
                &ws_runner,
                &audit,
                prompts,
                |round| {
                    print!("{}", round.agent_stdout);
                    if !round.agent_stderr.is_empty() {
                        eprint!("{}", round.agent_stderr);
                    }
                },
            )
            .map(|_| ())
        }
    };

    let _ = run::remove_egress_firewall_in_container(&vm_runner, session_id.as_str());
    let teardown_result = habitat_vm::launcher::teardown(&launched, &vm_runner, &audit);

    if let Err(e) = session_result {
        eprintln!("habitat run: {e}");
        print_detail_pointer(&s, &raw_audit, verbose);
        return ExitCode::FAILURE;
    }
    if let Err(e) = teardown_result {
        eprintln!("habitat run: teardown failed: {e}");
        return ExitCode::FAILURE;
    }
    println!("{}", s.green_bold("Session ended."));
    ExitCode::SUCCESS
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
