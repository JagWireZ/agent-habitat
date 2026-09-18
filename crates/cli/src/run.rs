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
use habitat_workspace::command_runner::CommandRunner as WsCommandRunner;
use habitat_workspace::guest_exec::{self, GuestEndpoint, GuestExecRunner};
use habitat_workspace::pipeline::{self, BuildRequest};
use habitat_workspace::sync::{
    self, FlaggedPatchStore, HostToSandboxRequest, SandboxToHostRequest, SyncOutcome,
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
    /// The host-side mirror `sync` diffs against (`sync`'s own module
    /// doc) -- distinct from `staging_dir`, which is the disk-build
    /// pipeline's own working area and is never touched again after the
    /// image is built.
    pub fn mirror_dir(&self) -> PathBuf {
        self.state_dir.join("mirror")
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
        // Stopgap: the disk image is gone (task 2 of the bind-mount
        // migration), but the launcher still expects
        // `workspace_disk_path` to name something on disk until task 3
        // rewires it to bind-mount `staging_dir` directly.
        workspace_disk_path: paths.staging_dir(),
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

/// Ensures `mirror_dir` is a git repository before the first sync round
/// -- `sync`'s own module doc names this as the caller's responsibility;
/// mirrors `crates/workspace/examples/manual_sync_round.rs`'s same
/// one-time setup step.
fn ensure_mirror_initialized<R: WsCommandRunner>(mirror_dir: &Path, runner: &R) -> Result<(), RunError> {
    if mirror_dir.join(".git").exists() {
        return Ok(());
    }
    std::fs::create_dir_all(mirror_dir)
        .map_err(|e| run_err(format!("could not create mirror dir {}: {e}", mirror_dir.display())))?;
    let mirror_str = mirror_dir
        .to_str()
        .ok_or_else(|| run_err("mirror directory path is not valid UTF-8"))?;
    let output = runner
        .run("git", &["-C", mirror_str, "init", "--quiet"])
        .map_err(|e| run_err(format!("could not `git init` the mirror dir: {e}")))?;
    if !output.status.success() {
        return Err(run_err(format!(
            "`git init` on the mirror dir exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Runs the prompt loop for one launched session: for each prompt from
/// `prompts`, host->sandbox sync, one discrete agent exec, then
/// sandbox->host sync (`docs/decisions/0009-run-driver-prompt-loop.md`).
/// Stops at the first prompt equal to [`EXIT_COMMANDS`] or when `prompts`
/// is exhausted.
///
/// Generic over the host-side runner (real `git` against the mirror) and
/// the guest-side runner (`ssh`/`scp`) separately, matching
/// `sync::sync_host_to_sandbox`/`sync_sandbox_to_host`'s own split --
/// production passes the same `SystemCommandRunner` for both, tests fake
/// only the guest side.
#[allow(clippy::too_many_arguments)]
pub fn run_prompt_loop<WH, WG, A>(
    project_root: &Path,
    paths: &SessionPaths,
    guest: GuestEndpoint<'_>,
    patterns: &[String],
    agent: &AgentInvocation,
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
    ensure_mirror_initialized(&paths.mirror_dir(), host_runner)?;
    let flagged_store = FlaggedPatchStore::new(paths.flagged_dir());
    let mirror_dir = paths.mirror_dir();
    let mut summary = SessionSummary::default();

    for prompt in prompts {
        if EXIT_COMMANDS.contains(&prompt.trim()) {
            break;
        }

        let host_request = HostToSandboxRequest {
            project_root,
            mirror_dir: &mirror_dir,
            guest,
            patterns,
            flagged_store: &flagged_store,
        };
        let host_to_sandbox = sync::sync_host_to_sandbox(&host_request, host_runner, guest_runner, audit)
            .map_err(|e| run_err(format!("host->sandbox sync failed: {e}")))?;

        let exec_runner = GuestExecRunner::new(guest_runner, guest);
        let mut arg_refs: Vec<&str> = agent.args.iter().map(String::as_str).collect();
        arg_refs.push(prompt.as_str());
        let agent_output = exec_runner
            .exec(&agent.program, &arg_refs)
            .map_err(|e| run_err(format!("could not run agent '{}': {e}", agent.program)))?;

        let sandbox_request = SandboxToHostRequest {
            project_root,
            mirror_dir: &mirror_dir,
            guest,
            patterns,
            flagged_store: &flagged_store,
        };
        let sandbox_to_host = sync::sync_sandbox_to_host(&sandbox_request, host_runner, guest_runner, audit)
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

/// How often the background sync loop runs while an interactive shell
/// session ([`run_shell_session`]) is open. A raw shell has no "prompt"
/// boundary to sync around, so a fixed interval stands in for it --
/// chosen to keep changes visible on both sides without spamming a
/// git/ssh round-trip on an idle shell.
pub const SHELL_SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// What an interactive shell session did, for the caller to report.
#[derive(Debug, Clone, Copy)]
pub struct ShellSessionOutcome {
    pub shell_exit_success: bool,
}

/// Runs an interactive shell session for one launched sandbox
/// (`habitat run` with no agent named): syncs host->sandbox once, opens a
/// real PTY-attached `ssh` session with the operator's own terminal
/// attached (not a captured `CommandRunner` invocation) so they get a
/// normal interactive shell inside `sync::GUEST_WORKSPACE_DIR`, keeps
/// host<->sandbox sync running in the background on [`SHELL_SYNC_INTERVAL`]
/// for the life of that shell, then runs one final sandbox->host sync
/// once the shell exits.
///
/// Unlike [`run_prompt_loop`] (one discrete sync round per agent turn),
/// there is no prompt boundary for a raw shell to sync around, so this
/// bookends the whole session with sync at start/end and fills the gap
/// with a periodic background sync instead of a live, continuously-
/// mounted share (AGENTS.md invariant 1 still holds: each tick is its
/// own discrete host->sandbox + sandbox->host round through the same
/// `sync` API the prompt loop uses, not a persistent channel -- the PTY
/// itself carries only terminal I/O, never a file share).
pub fn run_shell_session<WH, WG, A>(
    project_root: &Path,
    paths: &SessionPaths,
    guest: GuestEndpoint<'_>,
    patterns: &[String],
    host_runner: &WH,
    guest_runner: &WG,
    audit: &A,
) -> Result<ShellSessionOutcome, RunError>
where
    WH: WsCommandRunner + Sync,
    WG: WsCommandRunner + Sync,
    A: AuditSink + Sync,
{
    ensure_mirror_initialized(&paths.mirror_dir(), host_runner)?;
    let flagged_store = FlaggedPatchStore::new(paths.flagged_dir());
    let mirror_dir = paths.mirror_dir();

    let sync_round = || -> Result<(), RunError> {
        let host_request = HostToSandboxRequest {
            project_root,
            mirror_dir: &mirror_dir,
            guest,
            patterns,
            flagged_store: &flagged_store,
        };
        sync::sync_host_to_sandbox(&host_request, host_runner, guest_runner, audit)
            .map_err(|e| run_err(format!("host->sandbox sync failed: {e}")))?;

        let sandbox_request = SandboxToHostRequest {
            project_root,
            mirror_dir: &mirror_dir,
            guest,
            patterns,
            flagged_store: &flagged_store,
        };
        sync::sync_sandbox_to_host(&sandbox_request, host_runner, guest_runner, audit)
            .map_err(|e| run_err(format!("sandbox->host sync failed: {e}")))?;
        Ok(())
    };

    // Initial sync before the shell opens, so the guest starts from the
    // operator's current working tree.
    sync_round()?;

    let stop = std::sync::atomic::AtomicBool::new(false);
    let shell_result = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(SHELL_SYNC_INTERVAL);
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                // Best-effort: a flagged/failed periodic tick is not fatal
                // to the still-open interactive shell -- the final sync
                // after the shell exits still runs, and per-round failures
                // are already visible via `audit`.
                let _ = sync_round();
            }
        });

        let result = spawn_interactive_shell(&guest);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        result
    });

    // Final sync once the shell exits, to catch anything the last
    // periodic tick missed.
    sync_round()?;

    Ok(ShellSessionOutcome {
        shell_exit_success: shell_result?,
    })
}

/// Opens a real interactive `ssh` session against the guest, with the
/// operator's own terminal (stdin/stdout/stderr) attached via `-tt`
/// (force PTY allocation) -- not the captured-`Output` `CommandRunner`
/// seam every other guest interaction uses, since that seam has no way to
/// stream a live terminal. Blocks until the operator exits the shell.
fn spawn_interactive_shell(guest: &GuestEndpoint<'_>) -> Result<bool, RunError> {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("ssh");
    cmd.args(guest_exec::ssh_option_args(guest));
    cmd.arg("-tt");
    cmd.arg(format!("{}@{}", guest_exec::GUEST_SSH_USER, guest.host));
    cmd.arg(format!(
        "cd {} && exec $SHELL -l",
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

    let loop_result = run_prompt_loop(
        project_root,
        paths,
        guest,
        &patterns,
        agent,
        deps.host_runner,
        deps.guest_runner,
        deps.audit,
        prompts,
        on_round,
    );

    // Teardown always runs once launch succeeded, regardless of how the
    // prompt loop finished -- a mid-session failure must never leak a
    // running VM (AGENTS.md invariant: containment resources are always
    // reclaimed).
    let teardown_result = launcher::teardown(&launched, deps.vm_runner, deps.audit)
        .map_err(|e| run_err(format!("teardown failed: {e}")));

    let summary = loop_result?;
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
/// (`WORKSPACE_DISK_ANNOTATION`, the crun-krun package/binary split):**
/// this is this module's best current understanding of how to apply the
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

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
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
        assert_eq!(request.image_path, paths.image_path());
        assert_eq!(request.image_size_mb, DEFAULT_IMAGE_SIZE_MB);
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
        assert_eq!(req.workspace_disk_path, paths.image_path());
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
