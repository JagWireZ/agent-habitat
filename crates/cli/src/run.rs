//! `habitat run`'s session driver: assembles Phases 1-6's already-tested
//! subsystems into the full lifecycle `docs/plan.md` describes --
//! preflight -> disk build -> VM launch -> prompt loop with two-point
//! sync -> teardown -- deferring to each subsystem's own API rather than
//! reimplementing any of their logic here.
//!
//! **Prompt loop design:** see `docs/decisions/0009-run-driver-prompt-loop.md`.
//! Each operator prompt is one discrete guest exec (the agent named after
//! `--`, invoked once per prompt in a one-shot mode), wrapped by exactly
//! one `sync_host_to_sandbox` and one `sync_sandbox_to_host` call --
//! never a persistent connection to the guest.
//!
//! Egress (the local proxy, DNS forwarder, and per-session firewall
//! rules) is started once at session setup and torn down once at session
//! end; see [`start_egress`]/[`stop_egress`]. Neither is exercised by
//! this module's own generic, fake-driven tests (`run_full_session`'s
//! generic parameters cover preflight/build/launch/sync/teardown only) --
//! confirming the real proxy/DNS/firewall wiring needs real KVM, same as
//! every other real-network claim in this project
//! (`tests/manual/validate-egress.sh`).

use habitat_audit::AuditSink;
use habitat_egress::dialer::SystemDialer;
use habitat_egress::network_setup;
use habitat_install::Environment;
use habitat_policy::config::ProjectConfig;
use habitat_vm::command_runner::CommandRunner as VmCommandRunner;
use habitat_vm::guest_ssh;
use habitat_vm::launcher;
use habitat_vm::session::{LaunchRequest, SessionId};
use habitat_workspace::agent_state::{AgentStateSession, CopyReport};
use habitat_workspace::command_runner::CommandRunner as WsCommandRunner;
use habitat_workspace::guest_exec::{self, GuestEndpoint, GuestExecRunner};
use habitat_workspace::pipeline::{self, BuildRequest};
use habitat_workspace::sync::{
    self, FlaggedPatchStore, HostToSandboxRequest, MergeOutcome, SandboxToHostRequest, SyncOutcome,
};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Default path `habitat run` looks for a project config file at, absent
/// `--config`. Matches `docs/plan.md` Section 2.5's example
/// (`sandbox.yaml`).
pub const DEFAULT_CONFIG_PATH: &str = "sandbox.yaml";

/// A line the operator types ends the session instead of being sent to
/// the agent as a prompt.
pub const EXIT_COMMANDS: &[&str] = &["exit", "quit"];

/// The agent command named after `habitat run -- `. Must support a
/// one-shot, single-prompt invocation mode -- see `docs/decisions/
/// 0009-run-driver-prompt-loop.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInvocation {
    pub program: String,
    pub args: Vec<String>,
}

/// What `habitat run` does once the sandbox is up: either drop the
/// operator into an interactive shell inside it, or run a named agent in
/// the discrete, one-shot prompt loop (`docs/decisions/
/// 0009-run-driver-prompt-loop.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunMode {
    Shell,
    Agent(AgentInvocation),
}

/// Parsed `habitat run` arguments (everything after the `run` subcommand
/// word itself, including any `--verbose`/`-v` that landed after it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArgs {
    pub config_path: PathBuf,
    pub mode: RunMode,
}

/// Maps a named agent shorthand (`habitat run claude`) to the actual
/// guest-side binary the one-shot prompt loop invokes. `--
/// <program> [args...]` remains the escape hatch for any other agent
/// binary that supports the same one-shot invocation mode.
fn known_agent_binary(name: &str) -> Option<&'static str> {
    match name {
        "claude" => Some("claude-code"),
        "codex" => Some("codex"),
        "opencode" => Some("opencode"),
        _ => None,
    }
}

/// The named agent shorthands `habitat run` accepts, for error messages.
const KNOWN_AGENT_NAMES: &[&str] = &["claude", "codex", "opencode"];

/// Maps a guest-side agent binary (`known_agent_binary`'s output) to its
/// id in the agent state manifest (`habitat_policy::agent_state`). A custom
/// `-- <program>` agent has no entry and so gets no agent state at all --
/// only the three named shorthands are "known" enough to be handed
/// credentials.
pub fn agent_state_id_for_program(program: &str) -> Option<&'static str> {
    match program {
        "claude-code" => Some("claude"),
        "codex" => Some("codex"),
        "opencode" => Some("opencode"),
        _ => None,
    }
}

/// Which manifest agents a session may receive state for -- least
/// privilege by mode. A named agent gets only its own files (a `claude`
/// session never sees the Codex token); a custom `-- <program>` gets none;
/// an interactive shell, where the operator may run any agent, gets all.
pub fn agent_state_ids_for_mode(mode: &RunMode) -> Vec<String> {
    match mode {
        RunMode::Shell => habitat_policy::agent_state::known_agents(),
        RunMode::Agent(agent) => agent_state_id_for_program(&agent.program)
            .map(|id| vec![id.to_string()])
            .unwrap_or_default(),
    }
}

/// Opens this session's agent state under `~/.habitat/agents/`
/// (`habitat_workspace::agent_state`). `Ok(None)` when there is nothing to
/// do: no readable `$HOME`, or a custom agent with no manifest entries. An
/// `Err` is not fatal to the session -- the caller reports it and carries
/// on with the agent unauthenticated -- but it is never swallowed.
pub fn open_agent_state(
    home: Option<&Path>,
    mode: &RunMode,
) -> std::io::Result<Option<AgentStateSession>> {
    let ids = agent_state_ids_for_mode(mode);
    let (Some(home), false) = (home, ids.is_empty()) else {
        return Ok(None);
    };
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    AgentStateSession::open(home, &id_refs, launcher::GUEST_HOME_DIR).map(Some)
}

/// Seeds any missing staging file (`auth` and `config` alike) under
/// `~/.habitat/agents/` from the operator's real dotfiles on this host
/// (`.claude.json`, `.codex/auth.json`, etc.), gated entirely by the
/// project config's `agent_host_files` toggle -- disabled does nothing at
/// all, not even for `auth`. A no-op once a staging file exists. Nothing
/// to do (and an empty report) when `agent_state` is `None`.
pub fn agent_state_seed_missing_from_host<A: AuditSink>(
    agent_state: Option<&AgentStateSession>,
    enabled: bool,
    audit: &A,
) -> CopyReport {
    match agent_state {
        Some(state) => state.seed_missing_from_host(enabled, audit),
        None => CopyReport::default(),
    }
}

/// Copies this session's agent auth and config files into the guest.
/// Nothing to do (and an empty report) when `agent_state` is `None`.
pub fn agent_state_copy_in<R: WsCommandRunner, A: AuditSink>(
    agent_state: Option<&AgentStateSession>,
    guest: GuestEndpoint<'_>,
    runner: &R,
    audit: &A,
) -> CopyReport {
    match agent_state {
        Some(state) => state.copy_in(&GuestExecRunner::new(runner, guest), audit),
        None => CopyReport::default(),
    }
}

/// Copies changed agent auth files back out of the guest. Best-effort by
/// design: every rejection is already in the audit log, and a failure here
/// must never block the sync, the merge-back, or teardown.
pub fn agent_state_copy_out<R: WsCommandRunner, A: AuditSink>(
    agent_state: Option<&AgentStateSession>,
    guest: GuestEndpoint<'_>,
    runner: &R,
    audit: &A,
) -> CopyReport {
    match agent_state {
        Some(state) => state.copy_out(&GuestExecRunner::new(runner, guest), audit),
        None => CopyReport::default(),
    }
}

/// Subdirectory, under the operator's home, that [`log_habitat_event`]
/// appends to -- separate from `habitat-audit`'s own boundary audit log
/// (`habitat_policy::default_audit_log_path`, under XDG state), which is
/// a JSON-escaped security record kept elsewhere on purpose. This one is
/// a plain, human-readable breadcrumb trail colocated with `~/.habitat/`
/// itself, so an operator poking around that folder (e.g. to see why it
/// exists, or what last touched it) finds an explanation right there
/// instead of needing to know the audit log exists at all.
const LOG_HOME_SUBDIR: &str = ".habitat/logs";

/// Appends one timestamped line to `~/.habitat/logs/habitat.log`,
/// creating `~/.habitat/logs` (and so, on a brand-new installation,
/// `~/.habitat` itself) on first use, as `0700` like everything else
/// under `~/.habitat`. Agent state under `~/.habitat/agents/` is created
/// separately, per agent, only when that agent is actually run
/// ([`open_agent_state`]).
///
/// Best-effort and silent on failure: a read-only `$HOME` or a full disk
/// must never block a session over a convenience log.
pub fn log_habitat_event(home_dir: &Path, message: &str) {
    use std::io::Write;

    use std::os::unix::fs::DirBuilderExt;

    let dir = home_dir.join(LOG_HOME_SUBDIR);
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .is_err()
    {
        return;
    }
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{unix_secs} {message}\n");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("habitat.log"))
    {
        let _ = file.write_all(line.as_bytes());
    }
}

/// Parses `habitat run`'s own arguments: an optional `--config <path>`,
/// then either nothing (interactive shell), a named agent shorthand
/// (`claude`/`codex`/`opencode`) plus its own args, or `--
/// <program> [args...]` for an arbitrary agent command. `--verbose`/`-v`
/// may appear anywhere before the mode-selecting token (already handled
/// separately by `main`'s own global flag scan) and are otherwise
/// ignored here.
pub fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                let value = match args.get(i + 1) {
                    Some(v) if v != "--" => v,
                    _ => return Err("--config requires a path argument".to_string()),
                };
                config_path = PathBuf::from(value);
                i += 2;
            }
            "--verbose" | "-v" => i += 1,
            "--" => {
                let agent_argv = &args[i + 1..];
                let (program, rest) = agent_argv.split_first().ok_or_else(|| {
                    "expected an agent command after '--', e.g. `habitat run -- my-agent`"
                        .to_string()
                })?;
                return Ok(RunArgs {
                    config_path,
                    mode: RunMode::Agent(AgentInvocation {
                        program: program.clone(),
                        args: rest.to_vec(),
                    }),
                });
            }
            other if other.starts_with('-') => {
                return Err(format!(
                    "unrecognized argument '{other}' (expected '--config <path>', an agent \
                     name ({}), or '-- <command>')",
                    KNOWN_AGENT_NAMES.join("/")
                ));
            }
            name => {
                let program = known_agent_binary(name).ok_or_else(|| {
                    format!(
                        "unknown agent '{name}' (expected one of: {}, or '-- <command>' for a \
                         custom agent)",
                        KNOWN_AGENT_NAMES.join(", ")
                    )
                })?;
                return Ok(RunArgs {
                    config_path,
                    mode: RunMode::Agent(AgentInvocation {
                        program: program.to_string(),
                        args: args[i + 1..].to_vec(),
                    }),
                });
            }
        }
    }
    Ok(RunArgs {
        config_path,
        mode: RunMode::Shell,
    })
}

/// Where this session's on-disk state lives -- one fresh directory per
/// session, deleted at teardown alongside everything else disposable.
pub struct SessionPaths {
    pub state_dir: PathBuf,
}

impl SessionPaths {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        SessionPaths {
            state_dir: state_dir.into(),
        }
    }
    pub fn staging_dir(&self) -> PathBuf {
        self.state_dir.join("staging")
    }
    pub fn content_ruleset_path(&self) -> PathBuf {
        self.state_dir.join("effective-betterleaks.toml")
    }
    pub fn flagged_dir(&self) -> PathBuf {
        self.state_dir.join("flagged")
    }
    pub fn guest_ssh_key_path(&self) -> PathBuf {
        self.state_dir.join("guest-ssh-key")
    }
}

/// Removes the whole session state dir (staging copy, mirror, keys) on
/// every exit path -- success, early return, or panic --
/// instead of relying on each call site in `main.rs` to clean up, which
/// previously leaked every session's state into tmpfs `/tmp` (a leftover
/// staging dir per crashed/failed run, exhausting the per-user tmpfs
/// quota).
impl Drop for SessionPaths {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

/// Builds this session's disk-build request from a loaded project config
/// -- pure mapping, no I/O of its own (Phase 7 Task 3: confirm every
/// `ProjectConfig` field actually reaches its consumer).
pub fn build_request<'a>(project_root: &'a Path, paths: &SessionPaths, config: &ProjectConfig) -> BuildRequest<'a> {
    BuildRequest {
        project_root,
        staging_dir: paths.staging_dir(),
        project_config: config.clone(),
        content_ruleset_path: paths.content_ruleset_path(),
    }
}

/// The effective egress allowlist for a session: defaults plus this
/// project's own additions (`habitat_policy::egress_allowlist`'s own
/// additive-only guarantee -- never a default entry removed/overridden).
pub fn effective_egress_allowlist(config: &ProjectConfig) -> Vec<String> {
    habitat_policy::egress_allowlist::effective_entries(&config.egress_allowlist_additions)
}

/// Builds this session's VM launch request -- pure mapping, same
/// reasoning as [`build_request`].
#[allow(clippy::too_many_arguments)]
pub fn launch_request(
    session_id: SessionId,
    paths: &SessionPaths,
    config: &ProjectConfig,
    guest_image: String,
    egress_proxy_addr: SocketAddr,
    guest_ssh_public_key: String,
    guest_ssh_private_key_path: PathBuf,
) -> LaunchRequest {
    LaunchRequest {
        session_id,
        workspace_host_dir: paths.staging_dir(),
        guest_image,
        resource_limits: config.resource_limits.clone(),
        egress_proxy_addr,
        guest_ssh_public_key,
        guest_ssh_private_key_path,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunError {
    pub message: String,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RunError {}

fn run_err(message: impl Into<String>) -> RunError {
    RunError {
        message: message.into(),
    }
}

/// What one round of the prompt loop did, for the caller to print/log.
#[derive(Debug, Clone)]
pub struct PromptRoundOutcome {
    pub prompt: String,
    pub host_to_sandbox: SyncOutcome,
    pub agent_stdout: String,
    pub agent_stderr: String,
    pub agent_exit_success: bool,
    pub sandbox_to_host: SyncOutcome,
}

/// One full session's summary, for the caller to print/log.
#[derive(Debug, Clone, Default)]
pub struct SessionSummary {
    pub rounds: Vec<PromptRoundOutcome>,
}

/// Runs the prompt loop for one launched session: for each prompt from
/// `prompts`, host->sandbox sync, one discrete agent exec, then
/// sandbox->host sync (`docs/decisions/0009-run-driver-prompt-loop.md`).
/// Stops at the first prompt equal to [`EXIT_COMMANDS`] or when `prompts`
/// is exhausted. A blank (whitespace-only) line is skipped entirely --
/// no sync, no agent exec, no round in the summary -- rather than being
/// handed to the agent: most one-shot `--print`-style invocations treat
/// an empty prompt as a hard error, not a no-op turn.
///
/// Generic over the host-side runner (real `git`, run locally against the
/// bind-mounted workspace directory -- `sync::sync_host_to_sandbox`/
/// `sync_sandbox_to_host` no longer touch the guest at all) and the
/// guest-side runner (`ssh`/`scp`, used only for the agent exec itself)
/// separately -- production passes the same `SystemCommandRunner` for
/// both, tests fake only the guest side.
#[allow(clippy::too_many_arguments)]
pub fn run_prompt_loop<WH, WG, A>(
    project_root: &Path,
    paths: &SessionPaths,
    guest: GuestEndpoint<'_>,
    patterns: &[String],
    agent: &AgentInvocation,
    agent_state: Option<&AgentStateSession>,
    host_runner: &WH,
    guest_runner: &WG,
    audit: &A,
    prompts: impl IntoIterator<Item = String>,
    mut on_round: impl FnMut(&PromptRoundOutcome),
) -> Result<SessionSummary, RunError>
where
    WH: WsCommandRunner,
    WG: WsCommandRunner,
    A: AuditSink,
{
    let flagged_store = FlaggedPatchStore::new(paths.flagged_dir());
    let workspace_dir = paths.staging_dir();
    let mut summary = SessionSummary::default();

    for prompt in prompts {
        if EXIT_COMMANDS.contains(&prompt.trim()) {
            break;
        }
        if prompt.trim().is_empty() {
            continue;
        }

        let host_request = HostToSandboxRequest {
            project_root,
            workspace_dir: &workspace_dir,
            patterns,
            flagged_store: &flagged_store,
        };
        let host_to_sandbox = sync::sync_host_to_sandbox(&host_request, host_runner, audit)
            .map_err(|e| run_err(format!("host->sandbox sync failed: {e}")))?;

        let exec_runner = GuestExecRunner::new(guest_runner, guest);
        let mut arg_refs: Vec<&str> = agent.args.iter().map(String::as_str).collect();
        arg_refs.push(prompt.as_str());
        let agent_output = exec_runner
            .exec(&agent.program, &arg_refs)
            .map_err(|e| run_err(format!("could not run agent '{}': {e}", agent.program)))?;

        // The agent may have just refreshed a rotating OAuth token; pull it
        // back now rather than only at session end, so a crash between
        // rounds cannot leave the host holding a revoked refresh token.
        // Unchanged files cost one ssh and write nothing.
        agent_state_copy_out(agent_state, guest, guest_runner, audit);

        let sandbox_request = SandboxToHostRequest {
            project_root,
            workspace_dir: &workspace_dir,
            patterns,
            flagged_store: &flagged_store,
        };
        let sandbox_to_host = sync::sync_sandbox_to_host(&sandbox_request, host_runner, audit)
            .map_err(|e| run_err(format!("sandbox->host sync failed: {e}")))?;

        let round = PromptRoundOutcome {
            prompt,
            host_to_sandbox,
            agent_stdout: String::from_utf8_lossy(&agent_output.stdout).into_owned(),
            agent_stderr: String::from_utf8_lossy(&agent_output.stderr).into_owned(),
            agent_exit_success: agent_output.status.success(),
            sandbox_to_host,
        };
        on_round(&round);
        summary.rounds.push(round);
    }

    Ok(summary)
}

/// How often the background sync loop runs while an interactive session
/// ([`run_interactive_session`]) is open -- a raw shell or a named agent
/// run as a live, PTY-attached console. Neither has a "prompt" boundary
/// to sync around, so a fixed interval stands in for it -- chosen to keep
/// changes visible on both sides without spamming a git/ssh round-trip on
/// an idle session.
pub const SHELL_SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Agent auth files are re-checked for refreshed tokens every this many
/// interactive-session sync ticks (so every 30s at the default interval).
/// Each check is one `ssh` per auth file, which is cheap but not worth
/// doing every 5s; the caller's final copy-out after the session exits
/// catches the rest.
pub const SHELL_AGENT_STATE_TICKS_PER_COPY_OUT: u32 = 6;

/// Name of the sentinel file the guest can drop inside
/// [`sync::GUEST_WORKSPACE_DIR`] (visible host-side under the session's
/// staging directory, since it's the one bind-mounted directory both
/// sides share) to ask for a manual `git` merge-back of the workspace
/// repo's commits into the host's real repo, without waiting for the
/// session to end. A tiny `habitat-sync` script on the guest's `PATH`
/// just touches this file; the host-side background poll loop below
/// checks for it on every tick and removes it once handled -- no other
/// IPC channel needed, since `/workspace` is already the one thing both
/// sides can see.
pub const MANUAL_MERGE_REQUEST_FILE: &str = ".habitat-sync-request";

/// What an interactive session did, for the caller to report.
#[derive(Debug, Clone, Copy)]
pub struct InteractiveSessionOutcome {
    pub exit_success: bool,
}

/// Runs an interactive session for one launched sandbox: syncs once,
/// opens a real PTY-attached `ssh` session running `remote_command` with
/// the operator's own terminal attached (not a captured `CommandRunner`
/// invocation) -- `"$SHELL -l"` for `habitat run` with no agent named, or
/// a named agent's own program/args (built by [`agent_remote_command`])
/// run directly as a live console -- keeps host<->sandbox sync running
/// in the background on [`SHELL_SYNC_INTERVAL`] for the life of that
/// session, then runs one final sync round once it exits.
///
/// Unlike [`run_prompt_loop`] (one discrete sync round per agent turn),
/// there is no prompt boundary for a live PTY session to sync around, so
/// this bookends the whole session with sync at start/end and fills the
/// gap with a periodic background sync instead of a live, continuously-
/// mounted share (AGENTS.md invariant 1 still holds: each tick is its own
/// discrete host->sandbox + sandbox->host round through the same `sync`
/// API the prompt loop uses, not a persistent channel -- the PTY itself
/// carries only terminal I/O, never a file share). Each tick runs
/// sandbox->host *before* host->sandbox, the reverse of the prompt loop's
/// order: with no tool-call boundary to pin sync to, a file the guest
/// creates between ticks must be captured out to the host first, or the
/// next host->sandbox diff (built from a host snapshot that doesn't know
/// about it yet) would see it as deleted and remove it from the shared
/// workspace dir.
pub fn run_interactive_session<WH, A>(
    remote_command: &str,
    project_root: &Path,
    paths: &SessionPaths,
    guest: GuestEndpoint<'_>,
    patterns: &[String],
    agent_state: Option<&AgentStateSession>,
    host_runner: &WH,
    audit: &A,
) -> Result<InteractiveSessionOutcome, RunError>
where
    WH: WsCommandRunner + Sync,
    A: AuditSink + Sync,
{
    let flagged_store = FlaggedPatchStore::new(paths.flagged_dir());
    let workspace_dir = paths.staging_dir();

    let sync_round = || -> Result<(), RunError> {
        // Sandbox->host runs first: with no prompt/tool-call boundary to
        // pin sync to, a raw shell can create a file in the bind-mounted
        // workspace dir at any moment, including right before a tick. If
        // host->sandbox ran first, it would diff a host snapshot that
        // doesn't know about that file yet against the workspace dir that
        // does, produce a delete hunk for it, and apply that delete --
        // making a just-created guest file vanish on the next tick.
        // Capturing sandbox->host first ensures the host snapshot used by
        // host->sandbox already reflects anything the guest created before
        // this tick began.
        let sandbox_request = SandboxToHostRequest {
            project_root,
            workspace_dir: &workspace_dir,
            patterns,
            flagged_store: &flagged_store,
        };
        sync::sync_sandbox_to_host(&sandbox_request, host_runner, audit)
            .map_err(|e| run_err(format!("sandbox->host sync failed: {e}")))?;

        let host_request = HostToSandboxRequest {
            project_root,
            workspace_dir: &workspace_dir,
            patterns,
            flagged_store: &flagged_store,
        };
        sync::sync_host_to_sandbox(&host_request, host_runner, audit)
            .map_err(|e| run_err(format!("host->sandbox sync failed: {e}")))?;
        Ok(())
    };

    // Replays the workspace repo's commits onto a new host branch, if any
    // are new since the last such call -- the same function whether
    // triggered by the guest's manual sentinel file or by session end.
    let merge_now = || -> Result<MergeOutcome, RunError> {
        sync::merge_workspace_commits_to_host(project_root, &workspace_dir, host_runner, audit)
            .map_err(|e| run_err(format!("git merge-back failed: {e}")))
    };

    let manual_merge_request_path = workspace_dir.join(MANUAL_MERGE_REQUEST_FILE);

    // Initial sync before the session opens, so the guest starts from the
    // operator's current working tree.
    sync_round()?;

    let stop = std::sync::atomic::AtomicBool::new(false);
    let session_result = std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut ticks: u32 = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(SHELL_SYNC_INTERVAL);
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                ticks = ticks.wrapping_add(1);
                if ticks.is_multiple_of(SHELL_AGENT_STATE_TICKS_PER_COPY_OUT) {
                    // Best-effort; rejections are in the audit log.
                    agent_state_copy_out(agent_state, guest, host_runner, audit);
                }
                // Best-effort: a flagged/failed periodic tick is not fatal
                // to the still-open interactive shell -- the final sync
                // after the shell exits still runs, and per-round failures
                // are already visible via `audit`.
                let _ = sync_round();

                // The guest's `habitat-sync` helper just touches this
                // file inside the shared workspace directory to ask for a
                // manual merge-back mid-session -- remove it first so a
                // failed attempt doesn't get silently retried forever,
                // same best-effort treatment as the periodic sync above
                // (the failure is still visible via `audit`).
                if manual_merge_request_path.exists() {
                    let _ = std::fs::remove_file(&manual_merge_request_path);
                    let _ = merge_now();
                }
            }
        });

        let result = spawn_interactive_command(&guest, remote_command);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        result
    });

    // Final sync once the session exits, to catch anything the last
    // periodic tick missed, then a final merge-back so the session's
    // real commit history always makes it into the host repo before
    // teardown reclaims the workspace directory.
    sync_round()?;
    merge_now()?;

    Ok(InteractiveSessionOutcome {
        exit_success: session_result?,
    })
}

/// Upper bound on how long [`wait_for_guest_ssh`] polls before giving up.
/// Real-hardware boot path (`guest/entrypoint.sh`): DHCP alone can take
/// up to 10s before it gives up and continues anyway, then the workspace
/// and the workspace `chmod -R` run, all *before* `exec sshd` -- so the
/// guest's published SSH port can be seen as "up" (the TCP forward
/// itself is live the moment the container starts) well before anything
/// inside the guest is actually listening on it. 30s leaves comfortable
/// headroom over that worst case.
const GUEST_SSH_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait between [`wait_for_guest_ssh`] polling attempts.
const GUEST_SSH_READY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(300);

/// Blocks until the guest's `sshd` is actually ready to serve a real
/// session, by retrying a trivial `true` over SSH rather than firing the
/// operator's real shell/agent invocation at a guest that might still
/// reset the connection mid-handshake.
///
/// Without this, connecting immediately after `podman run` returns is a
/// real, observed race, not a hypothetical: the published port accepts
/// the TCP handshake right away (the forward itself is live as soon as
/// the container starts), but `guest/entrypoint.sh` doesn't `exec sshd`
/// until after DHCP (up to 10s) and a `chmod -R` over the bind-mounted
/// workspace have both finished -- an SSH attempt
/// in that window gets the connection reset mid-handshake
/// (`kex_exchange_identification: read: Connection reset by peer`)
/// instead of a clean "not up yet" signal to retry on.
///
/// Fails closed with the last error seen once [`GUEST_SSH_READY_TIMEOUT`]
/// elapses -- the caller is expected to tear the session down on error,
/// same as any other launch-time failure.
pub fn wait_for_guest_ssh<R: WsCommandRunner>(
    guest: GuestEndpoint<'_>,
    runner: &R,
) -> Result<(), RunError> {
    wait_for_guest_ssh_with(
        guest,
        runner,
        GUEST_SSH_READY_TIMEOUT,
        GUEST_SSH_READY_POLL_INTERVAL,
    )
}

/// [`wait_for_guest_ssh`] with an injectable timeout/poll interval, so
/// tests can exercise the retry-then-give-up path without actually
/// waiting [`GUEST_SSH_READY_TIMEOUT`] out.
fn wait_for_guest_ssh_with<R: WsCommandRunner>(
    guest: GuestEndpoint<'_>,
    runner: &R,
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
) -> Result<(), RunError> {
    let exec_runner = GuestExecRunner::new(runner, guest);
    let deadline = std::time::Instant::now() + timeout;
    let mut last_err: String;
    loop {
        last_err = match exec_runner.exec("true", &[]) {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => String::from_utf8_lossy(&output.stderr).trim().to_string(),
            Err(e) => e.to_string(),
        };
        if std::time::Instant::now() >= deadline {
            return Err(run_err(format!(
                "guest SSH never became ready within {timeout:?}: {last_err}"
            )));
        }
        std::thread::sleep(poll_interval);
    }
}

/// Builds the shell-quoted remote command for running a named agent as a
/// live, PTY-attached console (`run_interactive_session`'s
/// `remote_command`) -- the agent's own program and args, exactly as it
/// would be typed locally, with no trailing prompt argument. Reuses
/// `guest_exec::build_remote_command`, the same quoting
/// `GuestExecRunner`'s one-shot invocations already rely on, so a space,
/// quote, or other shell metacharacter in an agent arg is neutralized
/// identically in both paths.
pub fn agent_remote_command(agent: &AgentInvocation) -> String {
    let arg_refs: Vec<&str> = agent.args.iter().map(String::as_str).collect();
    guest_exec::build_remote_command(&[], &agent.program, &arg_refs)
}

/// Opens a real interactive `ssh` session against the guest running
/// `remote_command` (already shell-quoted, e.g. `"$SHELL -l"` or
/// [`agent_remote_command`]'s output), with the operator's own terminal
/// (stdin/stdout/stderr) attached via `-tt` (force PTY allocation) -- not
/// the captured-`Output` `CommandRunner` seam every other guest
/// interaction uses, since that seam has no way to stream a live
/// terminal. Blocks until the operator exits.
fn spawn_interactive_command(guest: &GuestEndpoint<'_>, remote_command: &str) -> Result<bool, RunError> {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("ssh");
    cmd.args(guest_exec::ssh_option_args(guest));
    cmd.arg("-tt");
    cmd.arg(format!("{}@{}", guest_exec::GUEST_SSH_USER, guest.host));
    cmd.arg(format!(
        "cd {} && exec {remote_command}",
        guest_exec::shell_quote(sync::GUEST_WORKSPACE_DIR)
    ));
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let status = cmd
        .status()
        .map_err(|e| run_err(format!("could not start interactive shell: {e}")))?;
    Ok(status.success())
}

/// Everything the full session driver needs, bundled so
/// [`run_full_session`]'s own signature doesn't grow one parameter per
/// subsystem. Each field is a reference/handle to a real (production) or
/// faked (test) implementation of that subsystem's own seam.
pub struct SessionDeps<'a, E, VR, WH, WG, A> {
    pub install_env: &'a E,
    pub vm_runner: &'a VR,
    pub host_runner: &'a WH,
    pub guest_runner: &'a WG,
    pub audit: &'a A,
}

/// Runs one complete session end to end: preflight -> disk build -> VM
/// launch -> prompt loop -> teardown. Fails closed at every stage --
/// teardown always runs once launch succeeded, even if the prompt loop
/// itself returns an error partway through, so a mid-session failure
/// never leaks a running VM.
#[allow(clippy::too_many_arguments)]
pub fn run_full_session<E, VR, WH, WG, A>(
    deps: &SessionDeps<'_, E, VR, WH, WG, A>,
    session_id: SessionId,
    project_root: &Path,
    paths: &SessionPaths,
    config: &ProjectConfig,
    guest_image: &str,
    egress_proxy_addr: SocketAddr,
    agent_state: Option<&AgentStateSession>,
    agent: &AgentInvocation,
    prompts: impl IntoIterator<Item = String>,
    on_round: impl FnMut(&PromptRoundOutcome),
) -> Result<SessionSummary, RunError>
where
    E: Environment,
    VR: VmCommandRunner,
    WH: WsCommandRunner,
    WG: WsCommandRunner,
    A: AuditSink,
{
    let secrets_scan_content_enabled = config.secrets_scan.content.is_enabled();
    habitat_install::run_preflight(deps.install_env, deps.audit, secrets_scan_content_enabled)
        .map_err(|e| run_err(format!("preflight failed: {e}")))?;

    let request = build_request(project_root, paths, config);
    pipeline::build(request, deps.host_runner)
        .map_err(|e| run_err(format!("disk build failed: {e}")))?;

    let keypair = guest_ssh::generate(&paths.guest_ssh_key_path(), deps.vm_runner)
        .map_err(|e| run_err(format!("could not generate session SSH key: {e}")))?;

    let launch_req = launch_request(
        session_id,
        paths,
        config,
        guest_image.to_string(),
        egress_proxy_addr,
        keypair.public_key,
        keypair.private_key_path.clone(),
    );

    let launched = launcher::launch(&launch_req, deps.vm_runner, deps.audit)
        .map_err(|e| run_err(format!("VM launch failed: {e}")))?;

    let patterns = if config.secrets_scan.filenames.is_enabled() {
        habitat_policy::blocklist::effective_patterns(&config.blocklist_additions)
    } else {
        Vec::new()
    };

    let guest = GuestEndpoint {
        host: &launched.guest_ssh_host,
        port: launched.guest_ssh_port,
        private_key_path: &launched.guest_ssh_private_key_path,
    };

    // Agent auth/config into the guest before the first prompt. A failure
    // here is reported in the audit log and leaves the agent
    // unauthenticated; it never fails the session.
    agent_state_copy_in(agent_state, guest, deps.guest_runner, deps.audit);

    let loop_result = run_prompt_loop(
        project_root,
        paths,
        guest,
        &patterns,
        agent,
        agent_state,
        deps.host_runner,
        deps.guest_runner,
        deps.audit,
        prompts,
        on_round,
    );

    // Same reasoning as the merge-back and teardown below: always attempt
    // the final auth copy-out, however the prompt loop finished, and while
    // the guest is still running.
    agent_state_copy_out(agent_state, guest, deps.guest_runner, deps.audit);

    // Same reasoning as teardown below: attempt the git merge-back
    // regardless of how the prompt loop finished, and always before
    // teardown reclaims the workspace directory the merge reads from.
    let merge_result = sync::merge_workspace_commits_to_host(
        project_root,
        &paths.staging_dir(),
        deps.host_runner,
        deps.audit,
    )
    .map_err(|e| run_err(format!("git merge-back failed: {e}")));

    // Teardown always runs once launch succeeded, regardless of how the
    // prompt loop finished -- a mid-session failure must never leak a
    // running VM (AGENTS.md invariant: containment resources are always
    // reclaimed).
    let teardown_result = launcher::teardown(&launched, deps.vm_runner, deps.audit)
        .map_err(|e| run_err(format!("teardown failed: {e}")));

    let summary = loop_result?;
    merge_result?;
    teardown_result?;
    Ok(summary)
}

/// Starts the egress side of a session: the local proxy, the DNS
/// forwarder pinning guest resolution to it, and the per-session
/// nftables firewall restricting the guest to reaching only the proxy.
/// Runs the proxy/DNS accept loops on detached background threads for
/// the life of the `habitat` process -- see this module's doc comment
/// and `docs/decisions/0009-run-driver-prompt-loop.md` for why no
/// graceful shutdown is attempted for those threads specifically (only
/// [`stop_egress`]'s firewall-rule removal is a real teardown step).
pub fn start_egress<A>(proxy_addr: SocketAddr, allowlist: Vec<String>, audit: Arc<A>)
where
    A: AuditSink + Send + Sync + 'static,
{
    let dialer = Arc::new(SystemDialer);
    std::thread::spawn(move || {
        let _ = habitat_egress::proxy::run(proxy_addr, allowlist, dialer, audit);
    });
    let dns_addr = network_setup::dns_listen_addr(proxy_addr);
    std::thread::spawn(move || {
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let _ = habitat_egress::dns::run(dns_addr, "1.1.1.1:53", running);
    });
}

/// Applies this session's egress firewall ruleset via `nft`. Generic over
/// `VR: VmCommandRunner` purely for reuse of the same seam the launcher
/// already depends on -- `nft` is otherwise unrelated to VM launch.
pub fn apply_egress_firewall<VR: VmCommandRunner>(
    runner: &VR,
    pasta_interface: &str,
    proxy_addr: SocketAddr,
) -> Result<(), RunError> {
    let ruleset = network_setup::build_egress_firewall_rules(pasta_interface, proxy_addr);
    run_nft(runner, &ruleset)
}

/// Removes this session's egress firewall tables. Idempotent: `nft`
/// reports "no such file" for an already-removed table, and that's not
/// treated as a hard failure -- matching `launcher::teardown`'s own
/// idempotency contract for `podman rm`/disk deletion.
pub fn remove_egress_firewall<VR: VmCommandRunner>(runner: &VR) -> Result<(), RunError> {
    let ruleset = format!(
        "delete table inet {table}_nat\ndelete table inet {table}\n",
        table = network_setup::FIREWALL_TABLE
    );
    match run_nft(runner, &ruleset) {
        Ok(()) => Ok(()),
        Err(e) if e.message.contains("No such file") => Ok(()),
        Err(e) => Err(e),
    }
}

fn run_nft<VR: VmCommandRunner>(runner: &VR, ruleset: &str) -> Result<(), RunError> {
    run_nft_in_netns(runner, ruleset, None)
}

/// Applies `ruleset` inside a container's own network namespace via
/// `nsenter --user --net --target <pid>`, or on the host's own default
/// namespace when `netns_pid` is `None`. A session's `pasta`-backed
/// interface lives inside the *container's* netns, not the host's, so
/// restricting it needs `nsenter` -- `tests/manual/validate-egress.sh`
/// worked this out by hand since `podman exec` doesn't work against
/// `krun` (`docs/decisions/0008-guest-exec-channel.md`) and there is no
/// other way to reach that namespace.
///
/// **Real-hardware caveat, same shape as this project's others
/// (the crun-krun package/binary split):** this is this module's best
/// current understanding of how to apply the
/// ruleset from the host side without `podman exec`, ported from
/// `validate-egress.sh`'s own hand-verified steps, but not yet exercised
/// by this exact function against real hardware -- see
/// `tests/manual/validate-egress.sh`'s own update for Phase 7.
fn run_nft_in_netns<VR: VmCommandRunner>(
    runner: &VR,
    ruleset: &str,
    netns_pid: Option<u32>,
) -> Result<(), RunError> {
    // `nft -f -` reads the ruleset from stdin, but `VmCommandRunner` has
    // no stdin-piping call -- writing it to a temp file and passing
    // `-f <path>` avoids adding a new capability to that seam for one
    // caller.
    let tmp = std::env::temp_dir().join(format!(
        "habitat-egress-firewall-{}-{}.nft",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::write(&tmp, ruleset)
        .map_err(|e| run_err(format!("could not write nft ruleset to {}: {e}", tmp.display())))?;
    let path_str = tmp
        .to_str()
        .ok_or_else(|| run_err("nft ruleset temp path is not valid UTF-8"))?;

    let result = match netns_pid {
        Some(pid) => {
            let pid_str = pid.to_string();
            runner.run(
                "nsenter",
                &[
                    "--user",
                    "--net",
                    "--target",
                    &pid_str,
                    "--",
                    "nft",
                    "-f",
                    path_str,
                ],
            )
        }
        None => runner.run("nft", &["-f", path_str]),
    };
    let _ = std::fs::remove_file(&tmp);
    let output = result.map_err(|e| run_err(format!("could not run `nft`: {e}")))?;
    if !output.status.success() {
        return Err(run_err(format!(
            "`nft` exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Resolves a running session's container PID via `podman inspect`, so
/// `nft` can be applied inside its network namespace
/// (`run_nft_in_netns`). Same real-hardware caveat as that function.
pub fn container_pid<VR: VmCommandRunner>(runner: &VR, session_id: &str) -> Result<u32, RunError> {
    let output = runner
        .run("podman", &["inspect", "-f", "{{.State.Pid}}", session_id])
        .map_err(|e| run_err(format!("could not run `podman inspect`: {e}")))?;
    if !output.status.success() {
        return Err(run_err(format!(
            "`podman inspect` exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|e| run_err(format!("could not parse container PID: {e}")))
}

/// Finds the session's `pasta`-backed interface name inside its own
/// network namespace: `ip -o link show`'s first interface that isn't
/// `lo`, ported directly from `tests/manual/validate-egress.sh`'s own
/// hand-verified parsing (see that script's own caveat that this is
/// "untested against real hardware whether this is always" the right
/// interface). Not a fixed, known-in-advance name -- `pasta` assigns it,
/// not this project.
pub fn discover_pasta_interface<VR: VmCommandRunner>(
    runner: &VR,
    netns_pid: u32,
) -> Result<String, RunError> {
    let pid_str = netns_pid.to_string();
    let output = runner
        .run(
            "nsenter",
            &["--user", "--net", "--target", &pid_str, "--", "ip", "-o", "link", "show"],
        )
        .map_err(|e| run_err(format!("could not run `nsenter ... ip link show`: {e}")))?;
    if !output.status.success() {
        return Err(run_err(format!(
            "`ip -o link show` exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // Format: "<idx>: <name>[@<peer>]: <flags> ..." -- take the name
        // between "N: " and the next "@" or ":".
        if let Some(rest) = line.split_once(": ").map(|(_, r)| r) {
            let name = rest.split(['@', ':']).next().unwrap_or("").trim();
            if !name.is_empty() && name != "lo" {
                return Ok(name.to_string());
            }
        }
    }
    Err(run_err("no non-loopback interface found in the session's network namespace"))
}

/// Applies this session's egress firewall ruleset inside the container's
/// own network namespace. Real-hardware caveat: see
/// [`run_nft_in_netns`].
pub fn apply_egress_firewall_in_container<VR: VmCommandRunner>(
    runner: &VR,
    session_id: &str,
    proxy_addr: SocketAddr,
) -> Result<(), RunError> {
    let pid = container_pid(runner, session_id)?;
    let iface = discover_pasta_interface(runner, pid)?;
    let ruleset = network_setup::build_egress_firewall_rules(&iface, proxy_addr);
    run_nft_in_netns(runner, &ruleset, Some(pid))
}

/// Removes this session's egress firewall tables from inside the
/// container's own network namespace. Idempotent, same reasoning as
/// [`remove_egress_firewall`]. A container that's already gone (the PID
/// lookup itself fails) means there's nothing left to remove either --
/// treated as already-clean, not an error.
pub fn remove_egress_firewall_in_container<VR: VmCommandRunner>(
    runner: &VR,
    session_id: &str,
) -> Result<(), RunError> {
    let pid = match container_pid(runner, session_id) {
        Ok(pid) => pid,
        Err(_) => return Ok(()),
    };
    let ruleset = format!(
        "delete table inet {table}_nat\ndelete table inet {table}\n",
        table = network_setup::FIREWALL_TABLE
    );
    match run_nft_in_netns(runner, &ruleset, Some(pid)) {
        Ok(()) => Ok(()),
        Err(e) if e.message.contains("No such file") => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use habitat_policy::resource_limits::ResourceLimitsConfig;
    use habitat_vm::command_runner::testing::FakeCommandRunner as VmFakeCommandRunner;

    /// Stands in for the guest's `sshd` coming up partway through
    /// [`wait_for_guest_ssh_with`]'s polling: every `ssh` invocation
    /// before the `succeed_after`th fails as if the guest reset the
    /// connection mid-handshake (`guest/entrypoint.sh` hasn't `exec
    /// sshd`'d yet); from then on it succeeds, same as a real `true`.
    struct FlakyGuestRunner {
        succeed_after: u32,
        calls: std::cell::Cell<u32>,
    }

    impl WsCommandRunner for FlakyGuestRunner {
        fn run_with_env(
            &self,
            _env: &[(&str, &str)],
            _program: &str,
            _args: &[&str],
        ) -> std::io::Result<std::process::Output> {
            use std::os::unix::process::ExitStatusExt;
            let n = self.calls.get() + 1;
            self.calls.set(n);
            let success = n > self.succeed_after;
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 << 8 }),
                stdout: Vec::new(),
                stderr: if success {
                    Vec::new()
                } else {
                    b"kex_exchange_identification: read: Connection reset by peer".to_vec()
                },
            })
        }
    }

    fn fake_guest<'a>(key_path: &'a Path) -> GuestEndpoint<'a> {
        GuestEndpoint {
            host: "127.0.0.1",
            port: 2222,
            private_key_path: key_path,
        }
    }

    #[test]
    fn wait_for_guest_ssh_with_succeeds_once_the_guest_stops_resetting_the_connection() {
        let key_path = PathBuf::from("/tmp/habitat-test-guest-ssh-key");
        let runner = FlakyGuestRunner {
            succeed_after: 2,
            calls: std::cell::Cell::new(0),
        };
        let result = wait_for_guest_ssh_with(
            fake_guest(&key_path),
            &runner,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_millis(1),
        );
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(runner.calls.get(), 3);
    }

    #[test]
    fn wait_for_guest_ssh_with_fails_closed_once_the_timeout_elapses() {
        let key_path = PathBuf::from("/tmp/habitat-test-guest-ssh-key");
        let runner = FlakyGuestRunner {
            succeed_after: u32::MAX,
            calls: std::cell::Cell::new(0),
        };
        let result = wait_for_guest_ssh_with(
            fake_guest(&key_path),
            &runner,
            std::time::Duration::from_millis(20),
            std::time::Duration::from_millis(5),
        );
        let err = result.expect_err("guest never becomes ready in this test");
        assert!(err.message.contains("Connection reset by peer"), "{err:?}");
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn agent_remote_command_quotes_a_bare_program_with_no_args() {
        let agent = AgentInvocation {
            program: "claude-code".to_string(),
            args: vec![],
        };
        assert_eq!(agent_remote_command(&agent), "'claude-code'");
    }

    #[test]
    fn agent_remote_command_quotes_args_including_metacharacters() {
        let agent = AgentInvocation {
            program: "claude-code".to_string(),
            args: vec!["--resume".to_string(), "it's a test".to_string()],
        };
        assert_eq!(
            agent_remote_command(&agent),
            "'claude-code' '--resume' 'it'\\''s a test'"
        );
    }

    #[test]
    fn parses_minimal_run_args_with_custom_agent_separator() {
        let parsed = parse_run_args(&args(&["--", "my-agent"])).unwrap();
        assert_eq!(parsed.config_path, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert_eq!(
            parsed.mode,
            RunMode::Agent(AgentInvocation {
                program: "my-agent".to_string(),
                args: vec![],
            })
        );
    }

    #[test]
    fn parses_config_flag_and_agent_args_with_separator() {
        let parsed = parse_run_args(&args(&[
            "--config",
            "sandbox.yaml",
            "--",
            "my-agent",
            "--print",
        ]))
        .unwrap();
        assert_eq!(parsed.config_path, PathBuf::from("sandbox.yaml"));
        assert_eq!(
            parsed.mode,
            RunMode::Agent(AgentInvocation {
                program: "my-agent".to_string(),
                args: vec!["--print".to_string()],
            })
        );
    }

    #[test]
    fn no_agent_and_no_separator_is_shell_mode() {
        let parsed = parse_run_args(&args(&[])).unwrap();
        assert_eq!(parsed.config_path, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert_eq!(parsed.mode, RunMode::Shell);
    }

    #[test]
    fn config_flag_alone_is_still_shell_mode() {
        let parsed = parse_run_args(&args(&["--config", "sandbox.yaml"])).unwrap();
        assert_eq!(parsed.config_path, PathBuf::from("sandbox.yaml"));
        assert_eq!(parsed.mode, RunMode::Shell);
    }

    #[test]
    fn named_agent_shorthand_maps_to_its_binary() {
        let parsed = parse_run_args(&args(&["claude"])).unwrap();
        assert_eq!(
            parsed.mode,
            RunMode::Agent(AgentInvocation {
                program: "claude-code".to_string(),
                args: vec![],
            })
        );
    }

    #[test]
    fn named_agent_shorthand_forwards_its_own_args() {
        let parsed = parse_run_args(&args(&["codex", "--print"])).unwrap();
        assert_eq!(
            parsed.mode,
            RunMode::Agent(AgentInvocation {
                program: "codex".to_string(),
                args: vec!["--print".to_string()],
            })
        );
    }

    #[test]
    fn opencode_shorthand_maps_to_its_own_binary() {
        let parsed = parse_run_args(&args(&["opencode"])).unwrap();
        assert_eq!(
            parsed.mode,
            RunMode::Agent(AgentInvocation {
                program: "opencode".to_string(),
                args: vec![],
            })
        );
    }

    #[test]
    fn unknown_agent_name_is_an_error() {
        let err = parse_run_args(&args(&["some-unknown-agent"])).unwrap_err();
        assert!(err.contains("some-unknown-agent"));
        assert!(err.contains("claude"));
    }

    #[test]
    fn empty_agent_command_after_separator_is_an_error() {
        let err = parse_run_args(&args(&["--"])).unwrap_err();
        assert!(err.contains("agent command"));
    }

    #[test]
    fn missing_config_value_is_an_error() {
        // `--` can't double as `--config`'s value, since it's reserved as
        // the custom-agent separator.
        let err = parse_run_args(&args(&["--config", "--", "claude-code"])).unwrap_err();
        assert!(err.contains("--config"));
    }

    #[test]
    fn ignores_verbose_flags_before_the_mode_token() {
        let parsed = parse_run_args(&args(&["--verbose", "--", "my-agent"])).unwrap();
        assert_eq!(
            parsed.mode,
            RunMode::Agent(AgentInvocation {
                program: "my-agent".to_string(),
                args: vec![],
            })
        );
    }

    #[test]
    fn unrecognized_flag_is_an_error() {
        let err = parse_run_args(&args(&["--bogus"])).unwrap_err();
        assert!(err.contains("--bogus"));
    }

    #[test]
    fn build_request_carries_project_config_and_session_paths_through() {
        let mut config = ProjectConfig::default();
        config.blocklist_additions = vec!["*.mysecret".to_string()];
        let paths = SessionPaths::new("/tmp/habitat-test-session");
        let project_root = Path::new("/tmp/habitat-test-project");
        let request = build_request(project_root, &paths, &config);
        assert_eq!(request.project_root, project_root);
        assert_eq!(request.staging_dir, paths.staging_dir());
        assert_eq!(
            request.project_config.blocklist_additions,
            vec!["*.mysecret".to_string()]
        );
        assert_eq!(request.content_ruleset_path, paths.content_ruleset_path());
    }

    #[test]
    fn effective_egress_allowlist_adds_project_entries_without_dropping_defaults() {
        let mut config = ProjectConfig::default();
        config.egress_allowlist_additions = vec!["internal.registry.example".to_string()];
        let effective = effective_egress_allowlist(&config);
        assert!(effective.contains(&"internal.registry.example".to_string()));
        assert!(effective.len() > 1, "defaults must still be present");
    }

    #[test]
    fn launch_request_carries_resource_limits_from_config() {
        let mut config = ProjectConfig::default();
        config.resource_limits = ResourceLimitsConfig {
            cpus: 4.0,
            memory_mb: 8192,
        };
        let paths = SessionPaths::new("/tmp/habitat-test-session-2");
        let req = launch_request(
            SessionId::from_name("habitat-test-launch-request").unwrap(),
            &paths,
            &config,
            "localhost/habitat-guest:alpine".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
            "ssh-ed25519 AAAA".to_string(),
            PathBuf::from("/tmp/habitat-test-session-2/guest-ssh-key"),
        );
        assert_eq!(req.resource_limits.cpus, 4.0);
        assert_eq!(req.resource_limits.memory_mb, 8192);
        assert_eq!(req.workspace_host_dir, paths.staging_dir());
    }

    /// Fresh, uniquely-named directory under the system temp dir, same
    /// pattern used throughout this crate's own tests (e.g.
    /// `run_nft_in_netns`) rather than pulling in a `tempfile` dev-
    /// dependency the rest of the workspace doesn't use.
    fn fresh_fake_home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "habitat-test-home-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn agent_invocation(program: &str) -> AgentInvocation {
        AgentInvocation {
            program: program.to_string(),
            args: Vec::new(),
        }
    }

    #[test]
    fn named_agents_map_to_their_manifest_ids_and_custom_ones_do_not() {
        assert_eq!(agent_state_id_for_program("claude-code"), Some("claude"));
        assert_eq!(agent_state_id_for_program("codex"), Some("codex"));
        assert_eq!(agent_state_id_for_program("opencode"), Some("opencode"));
        assert_eq!(agent_state_id_for_program("my-custom-agent"), None);
        // Every shorthand `habitat run` accepts has an id, so no named
        // agent silently runs without its credentials.
        for name in KNOWN_AGENT_NAMES {
            let program = known_agent_binary(name).unwrap();
            assert!(agent_state_id_for_program(program).is_some(), "{name}");
        }
    }

    #[test]
    fn a_named_agent_session_is_scoped_to_exactly_that_agent() {
        let mode = RunMode::Agent(agent_invocation("claude-code"));
        assert_eq!(agent_state_ids_for_mode(&mode), vec!["claude".to_string()]);
    }

    #[test]
    fn a_custom_agent_session_gets_no_agent_state() {
        let mode = RunMode::Agent(agent_invocation("my-custom-agent"));
        assert!(agent_state_ids_for_mode(&mode).is_empty());
    }

    #[test]
    fn a_shell_session_is_scoped_to_every_known_agent() {
        assert_eq!(
            agent_state_ids_for_mode(&RunMode::Shell),
            vec![
                "claude".to_string(),
                "codex".to_string(),
                "opencode".to_string()
            ]
        );
    }

    #[test]
    fn open_agent_state_is_a_noop_without_a_home_or_for_a_custom_agent() {
        let home = fresh_fake_home("agent-state-noop");
        let custom = RunMode::Agent(agent_invocation("my-custom-agent"));
        assert!(open_agent_state(Some(&home), &custom).unwrap().is_none());
        assert!(open_agent_state(None, &RunMode::Shell).unwrap().is_none());
        // Nothing was created for either.
        assert!(!home.join(".habitat").exists());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn open_agent_state_creates_only_the_named_agents_private_directory() {
        use std::os::unix::fs::PermissionsExt;
        let home = fresh_fake_home("agent-state-open");
        let mode = RunMode::Agent(agent_invocation("codex"));
        let state = open_agent_state(Some(&home), &mode).unwrap().unwrap();
        assert_eq!(state.agents(), vec!["codex"]);
        let agent_dir = home.join(".habitat/agents/codex");
        assert!(agent_dir.is_dir());
        assert_eq!(
            std::fs::metadata(&agent_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!home.join(".habitat/agents/claude").exists());
        drop(state);
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn log_habitat_event_creates_habitat_dir_and_appends_a_line() {
        let home = fresh_fake_home("log-event");
        log_habitat_event(&home, "ran habitat run -- claude-code");

        let log_path = home.join(".habitat/logs/habitat.log");
        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(contents.ends_with("ran habitat run -- claude-code\n"));

        log_habitat_event(&home, "ran habitat run (shell)");
        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(contents.lines().count(), 2, "second call should append, not overwrite");

        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&home.join(".habitat")), 0o700);
        assert_eq!(mode(&home.join(".habitat/logs")), 0o700);

        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn container_pid_parses_podman_inspect_output() {
        let runner = VmFakeCommandRunner::default()
            .with_ok("podman inspect -f {{.State.Pid}} habitat-test", "12345\n");
        let pid = container_pid(&runner, "habitat-test").unwrap();
        assert_eq!(pid, 12345);
    }

    #[test]
    fn container_pid_fails_closed_on_non_numeric_output() {
        let runner =
            VmFakeCommandRunner::default().with_ok("podman inspect -f {{.State.Pid}} habitat-test", "");
        assert!(container_pid(&runner, "habitat-test").is_err());
    }

    #[test]
    fn discover_pasta_interface_skips_loopback() {
        let runner = VmFakeCommandRunner::default().with_ok(
            "nsenter --user --net --target 12345 -- ip -o link show",
            "1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN\n\
             2: pasta0@if0: <BROADCAST,MULTICAST,UP> mtu 65520 qdisc noqueue state UNKNOWN\n",
        );
        let iface = discover_pasta_interface(&runner, 12345).unwrap();
        assert_eq!(iface, "pasta0");
    }

    #[test]
    fn discover_pasta_interface_fails_closed_when_only_loopback_present() {
        let runner = VmFakeCommandRunner::default().with_ok(
            "nsenter --user --net --target 12345 -- ip -o link show",
            "1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN\n",
        );
        assert!(discover_pasta_interface(&runner, 12345).is_err());
    }

    #[test]
    fn apply_egress_firewall_writes_and_runs_nft() {
        let runner = VmFakeCommandRunner::default().with_ok("nft", "");
        // `nft`'s argv includes a temp-file path that isn't predictable
        // ahead of time, so key against a runner that answers `nft` with
        // no args at all -- FakeCommandRunner keys on exact program+args,
        // so this deliberately checks the failure path (unconfigured
        // invocation) is a clean error rather than a panic.
        let result = apply_egress_firewall(&runner, "pasta0", "127.0.0.1:8443".parse().unwrap());
        assert!(result.is_err());
    }
}
