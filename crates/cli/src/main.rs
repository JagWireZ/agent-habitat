//! `habitat` -- the operator-facing CLI entrypoint.
//!
//! Phase 1 wires up two subcommands against the Phase 0 skeleton:
//! - `habitat install` -- runs `habitat-install::run_install_checks`.
//! - `habitat run` -- runs `habitat-install::run_preflight` and then stops;
//!   the rest of the session lifecycle (disk build, VM launch, prompt
//!   loop, teardown) is assembled in Phase 7 from Phases 2-6.
//!
//! No arg-parsing dependency is taken here: with no dependency-fetch
//! access in this environment (see Phase 1 implementation notes) and only
//! two subcommands to recognize, hand-rolled parsing is simpler and has
//! fewer moving parts than pulling in a framework for it.

use habitat_install::{
    install_report, preflight_report, run_install_checks, run_preflight, CheckStatus,
    SystemEnvironment,
};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("install") => cmd_install(),
        Some("run") => cmd_run(),
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

/// Prints one line per check: found or missing, with the same message the
/// gate would report on failure. `habitat install` is still verify-only --
/// this only changes what's displayed, not what's on the host -- so the
/// checklist is safe to print even when the run is ultimately going to
/// fail.
fn print_checklist(statuses: &[CheckStatus]) {
    println!("Host prerequisite check:");
    for status in statuses {
        match &status.result {
            Ok(()) => println!("  [ ok ] {:<18} found", status.check.name()),
            Err(f) => println!("  [MISSING] {:<14} {}", status.check.name(), f.message),
        }
    }
    println!();
}

fn cmd_install() -> ExitCode {
    let env = SystemEnvironment;
    let audit = audit_sink();
    print_checklist(&install_report(&env));
    match run_install_checks(&env, &audit) {
        Ok(()) => {
            println!("habitat install: all checks passed.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("habitat install: {e}");
            eprintln!(
                "see the audit log at {} for details",
                audit.path().display()
            );
            ExitCode::FAILURE
        }
    }
}

fn cmd_run() -> ExitCode {
    let env = SystemEnvironment;
    let audit = audit_sink();
    print_checklist(&preflight_report(&env));
    match run_preflight(&env, &audit) {
        Ok(()) => {
            // Phase 1 stops here. Phases 2-6 (disk build, VM launch,
            // two-point sync, egress, full audit) are assembled behind
            // this point in Phase 7.
            eprintln!(
                "habitat run: preflight passed; session lifecycle not yet implemented (Phase 7)."
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("habitat run: {e}");
            eprintln!(
                "see the audit log at {} for details",
                audit.path().display()
            );
            ExitCode::FAILURE
        }
    }
}
