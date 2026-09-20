//! The two-point host<->sandbox sync mechanism (`docs/plan.md` Section 2.2).
//!
//! Both directions: detect changes (no-op if none -- nothing generated,
//! applied, or logged), produce a real unified diff, run it through the
//! validation gate ([`patch::extract_touched_paths`], the blocklist
//! re-check, the content-ruleset special case, and
//! [`patch::structurally_valid`]) -- anything that fails is
//! [`SyncOutcome::Flagged`], never silently merged or dropped (`AGENTS.md`
//! Section 2, invariant 10) -- and only then apply, to the shared
//! workspace directory for host->sandbox or the real host working
//! directory for sandbox->host (invariant 3: the applied patch is the
//! authoritative change record).
//!
//! **There is no separate host-only mirror.** `workspace_dir` is the
//! disposable, git-seeded staging directory `crate::pipeline`/
//! `crate::gitseed` built and bind-mounted into the guest at
//! [`GUEST_WORKSPACE_DIR`] -- host and guest see the exact same physical
//! directory and the exact same `.git`. That directory is both what the
//! agent sees under `git_history` config *and* the sync diff baseline;
//! there is nothing else to keep in sync with it.
//!
//! Validate-before-mutate is still preserved without a persistent mirror:
//! `sync_host_to_sandbox` builds an ephemeral, blocklist-filtered scratch
//! snapshot of `project_root` each round
//! (`crate::staging::build_staging_dir`) and diffs it against the live
//! workspace directory via `git diff --no-index` -- read-only, never
//! touching the live tree -- so an invalid patch can still be flagged and
//! discarded before anything the agent can see is touched. Only a patch
//! that passes validation gets applied to the live directory.
//!
//! **SSH plays no part in sync.** Every git operation here (`git apply
//! --check`/`git apply`, `git add`, `git commit`, `git status`, `git
//! diff`) runs locally on the host directly against the bind-mounted
//! workspace directory, via the same synthetic-identity mechanism
//! (`crate::gitseed::run_git_with_identity`) already in place. SSH
//! (`crate::guest_exec::GuestExecRunner`) is reserved for what actually
//! needs the guest: invoking the agent process, and the interactive shell
//! session -- neither of which lives in this module.
//!
//! Sync's own `"habitat sync"` bookkeeping commits land in the same
//! repo/`.git` the agent's own `git log` shows, alongside whatever
//! `git_history` mode produced -- no separate, host-only git layer.
//!
//! No code path here ever pushes commits or configures a remote
//! (invariant 4), pinned by `tests/adversarial/sync_patch_validation.rs`.

use crate::command_runner::CommandRunner;
use crate::gitseed::run_git_with_identity;
use crate::patch;
use crate::staging;
use habitat_audit::{AuditEvent, AuditSink, EventKind};
use habitat_policy::blocklist;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Where, inside the guest, the workspace directory is bind-mounted --
/// confirmed against a real booted guest by `tests/manual/validate-sync.sh`.
pub const GUEST_WORKSPACE_DIR: &str = "/workspace";

/// Commit message for every sync-driven commit -- distinct from
/// `crate::gitseed`'s initial-seed message.
const SYNC_COMMIT_MESSAGE: &str = "habitat sync";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDirection {
    HostToSandbox,
    SandboxToHost,
}

impl SyncDirection {
    pub fn tag(self) -> &'static str {
        match self {
            SyncDirection::HostToSandbox => "host-to-sandbox",
            SyncDirection::SandboxToHost => "sandbox-to-host",
        }
    }
}

impl fmt::Display for SyncDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncError {
    pub message: String,
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sync: {}", self.message)
    }
}

impl std::error::Error for SyncError {}

fn err(message: impl Into<String>) -> SyncError {
    SyncError {
        message: message.into(),
    }
}

/// Why a patch was flagged for review instead of applied -- never
/// collapsed into a generic error (`AGENTS.md` Section 2, invariant 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagReason {
    /// `git apply --check` rejected the patch against the real arrival tree.
    MalformedPatch(String),
    /// The patch re-introduces a path the blocklist would have stripped
    /// on the original build.
    BlocklistedPathReintroduced(Vec<String>),
    /// The patch touches the project's `betterleaks.toml`, routed here
    /// unconditionally regardless of structural validity -- see
    /// `docs/decisions/0007-content-secrets-scan-snapshot.md`.
    ContentRulesetMidSessionEdit,
}

impl FlagReason {
    pub fn description(&self) -> String {
        match self {
            FlagReason::MalformedPatch(detail) => format!("malformed patch: {detail}"),
            FlagReason::BlocklistedPathReintroduced(paths) => format!(
                "patch re-introduces blocklisted path(s): {}",
                paths.join(", ")
            ),
            FlagReason::ContentRulesetMidSessionEdit => {
                "patch touches betterleaks.toml -- routed for review per \
                 docs/decisions/0007-content-secrets-scan-snapshot.md"
                    .to_string()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Nothing changed on the relevant side -- no patch was generated,
    /// nothing was applied, nothing was logged.
    NoOp,
    Applied {
        direction: SyncDirection,
        patch: String,
        touched_paths: Vec<String>,
    },
    Flagged {
        direction: SyncDirection,
        reason: FlagReason,
        patch: String,
    },
}

/// Persists a flagged patch for operator review. Each flagged patch gets a
/// `<timestamp>-<direction>.patch` file and a sibling `.reason.txt`.
pub struct FlaggedPatchStore {
    dir: PathBuf,
}

impl FlaggedPatchStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FlaggedPatchStore { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn record(
        &self,
        direction: SyncDirection,
        reason: &FlagReason,
        patch: &str,
    ) -> io::Result<PathBuf> {
        std::fs::create_dir_all(&self.dir)?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let base = self.dir.join(format!("{ts}-{direction}"));
        std::fs::write(base.with_extension("patch"), patch)?;
        std::fs::write(base.with_extension("reason.txt"), reason.description())?;
        Ok(base)
    }
}

/// The non-structural half of the validation gate: content-ruleset
/// special case, then the blocklist re-check. Shared by both directions;
/// the structural half ([`patch::structurally_valid`]) runs separately per
/// direction against its own real arrival tree.
fn non_structural_gate(patch: &str, patterns: &[String]) -> (Vec<String>, Option<FlagReason>) {
    let touched = patch::extract_touched_paths(patch);
    if patch::touches_content_ruleset_file(&touched) {
        return (touched, Some(FlagReason::ContentRulesetMidSessionEdit));
    }
    let blocked: Vec<String> = touched
        .iter()
        .filter(|p| blocklist::is_blocked(patterns, p))
        .cloned()
        .collect();
    if !blocked.is_empty() {
        return (
            touched,
            Some(FlagReason::BlocklistedPathReintroduced(blocked)),
        );
    }
    (touched, None)
}

fn record_flagged(
    store: &FlaggedPatchStore,
    direction: SyncDirection,
    reason: &FlagReason,
    patch: &str,
) -> Result<(), SyncError> {
    store
        .record(direction, reason, patch)
        .map_err(|e| err(format!("could not persist flagged patch for review: {e}")))?;
    Ok(())
}

fn emit_flagged<A: AuditSink>(audit: &A, direction: SyncDirection, reason: &FlagReason) {
    let _ = audit.record(&AuditEvent::now(
        EventKind::SyncFlagged,
        Some(direction.tag()),
        reason.description(),
    ));
    if matches!(reason, FlagReason::ContentRulesetMidSessionEdit) {
        let _ = audit.record(&AuditEvent::now(
            EventKind::ContentRulesetMidSessionEdit,
            Some(direction.tag()),
            "sync patch touched betterleaks.toml",
        ));
    }
}

fn emit_applied<A: AuditSink>(audit: &A, direction: SyncDirection, touched_paths: &[String]) {
    let _ = audit.record(&AuditEvent::now(
        EventKind::SyncApplied,
        Some(direction.tag()),
        format!(
            "{} file(s): {}",
            touched_paths.len(),
            touched_paths.join(", ")
        ),
    ));
}

/// `git add -A` + `git commit --allow-empty` under the synthetic identity,
/// against `dir` directly -- shared by both directions, since both now
/// commit straight into the one shared workspace repo.
fn commit_with_synthetic_identity<R: CommandRunner>(
    runner: &R,
    dir: &Path,
    message: &str,
) -> Result<(), SyncError> {
    let dir_str = dir
        .to_str()
        .ok_or_else(|| err("workspace directory path is not valid UTF-8"))?;
    run_git_with_identity(runner, dir_str, &["add", "-A"]).map_err(|e| err(e.to_string()))?;
    run_git_with_identity(
        runner,
        dir_str,
        &["commit", "--quiet", "--allow-empty", "-m", message],
    )
    .map_err(|e| err(e.to_string()))
}

/// Always runs `git apply` with `GIT_CEILING_DIRECTORIES` pinned to
/// `dir`'s own parent (`patch::git_apply_ceiling`). Without it, a *new
/// file* patch applied to `project_root` (not its own git repo) silently
/// no-ops -- `git apply` prints `Skipped patch` and exits 0 -- if
/// `project_root` happens to sit inside some unrelated enclosing repo.
fn apply_patch_to_dir<R: CommandRunner>(
    runner: &R,
    dir: &Path,
    patch_text: &str,
) -> Result<(), SyncError> {
    let tmp = patch::write_temp_patch_file(patch_text).map_err(|e| err(e.to_string()))?;
    let result = (|| {
        let dir_str = dir
            .to_str()
            .ok_or_else(|| err("target directory path is not valid UTF-8"))?;
        let patch_path = tmp
            .to_str()
            .ok_or_else(|| err("temp patch path is not valid UTF-8"))?;
        let ceiling = patch::git_apply_ceiling(dir).map_err(|e| err(e.to_string()))?;
        let output = runner
            .run_with_env(
                &[(patch::GIT_CEILING_DIRECTORIES_VAR, ceiling.as_str())],
                "git",
                &["-C", dir_str, "apply", patch_path],
            )
            .map_err(|e| err(format!("could not run `git apply`: {e}")))?;
        if !output.status.success() {
            return Err(err(format!(
                "`git apply` exited non-zero applying to {}: {}",
                dir.display(),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Everything needed to run one host->sandbox sync round.
pub struct HostToSandboxRequest<'a> {
    pub project_root: &'a Path,
    /// The disposable, git-seeded staging directory bind-mounted into the
    /// guest at [`GUEST_WORKSPACE_DIR`] (see module doc) -- host and
    /// guest see the same physical directory.
    pub workspace_dir: &'a Path,
    pub patterns: &'a [String],
    pub flagged_store: &'a FlaggedPatchStore,
}

/// Host->sandbox sync, run immediately before each prompt: builds an
/// ephemeral, blocklist-filtered snapshot of `project_root`, diffs it
/// read-only against the live workspace directory, re-filters that diff
/// through the blocklist, and only then applies it to the workspace
/// directory the guest already has bind-mounted.
pub fn sync_host_to_sandbox<R: CommandRunner, A: AuditSink>(
    request: &HostToSandboxRequest<'_>,
    runner: &R,
    audit: &A,
) -> Result<SyncOutcome, SyncError> {
    let scratch = scratch_dir_path("host-to-sandbox");
    let build_result = staging::build_staging_dir(request.project_root, &scratch, request.patterns, None)
        .map_err(|e| err(format!("could not stage a fresh host snapshot: {e}")));
    if let Err(e) = build_result {
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(e);
    }

    let diff_result = diff_no_index(runner, request.workspace_dir, &scratch);
    let _ = std::fs::remove_dir_all(&scratch);
    let diff = diff_result?;

    if diff.trim().is_empty() {
        return Ok(SyncOutcome::NoOp);
    }

    let (touched, flag) = non_structural_gate(&diff, request.patterns);
    if let Some(reason) = flag {
        record_flagged(
            request.flagged_store,
            SyncDirection::HostToSandbox,
            &reason,
            &diff,
        )?;
        emit_flagged(audit, SyncDirection::HostToSandbox, &reason);
        return Ok(SyncOutcome::Flagged {
            direction: SyncDirection::HostToSandbox,
            reason,
            patch: diff,
        });
    }

    let structurally_ok = patch::structurally_valid(runner, request.workspace_dir, &diff)
        .map_err(|e| err(e.to_string()))?;
    if !structurally_ok {
        let reason = FlagReason::MalformedPatch(
            "`git apply --check` rejected this patch against the live workspace directory"
                .to_string(),
        );
        record_flagged(
            request.flagged_store,
            SyncDirection::HostToSandbox,
            &reason,
            &diff,
        )?;
        emit_flagged(audit, SyncDirection::HostToSandbox, &reason);
        return Ok(SyncOutcome::Flagged {
            direction: SyncDirection::HostToSandbox,
            reason,
            patch: diff,
        });
    }

    apply_patch_to_dir(runner, request.workspace_dir, &diff)?;
    commit_with_synthetic_identity(runner, request.workspace_dir, SYNC_COMMIT_MESSAGE)?;

    emit_applied(audit, SyncDirection::HostToSandbox, &touched);
    Ok(SyncOutcome::Applied {
        direction: SyncDirection::HostToSandbox,
        patch: diff,
        touched_paths: touched,
    })
}

/// Everything needed to run one sandbox->host sync round.
pub struct SandboxToHostRequest<'a> {
    pub project_root: &'a Path,
    /// See [`HostToSandboxRequest::workspace_dir`].
    pub workspace_dir: &'a Path,
    pub patterns: &'a [String],
    pub flagged_store: &'a FlaggedPatchStore,
}

/// Sandbox->host sync, run immediately after each tool call: detects
/// changes the agent made directly in the (bind-mounted, shared)
/// workspace directory, commits them into that same repo, produces a
/// patch, and -- once validated -- applies it directly to the real host
/// working directory.
pub fn sync_sandbox_to_host<R: CommandRunner, A: AuditSink>(
    request: &SandboxToHostRequest<'_>,
    runner: &R,
    audit: &A,
) -> Result<SyncOutcome, SyncError> {
    let workspace_str = request
        .workspace_dir
        .to_str()
        .ok_or_else(|| err("workspace directory path is not valid UTF-8"))?;

    let status = capture_git(runner, workspace_str, &["status", "--porcelain"])?;
    if status.is_empty() {
        return Ok(SyncOutcome::NoOp);
    }

    commit_with_synthetic_identity(runner, request.workspace_dir, SYNC_COMMIT_MESSAGE)?;

    let patch_text = capture_git(runner, workspace_str, &["diff", "HEAD~1", "HEAD"])?;

    let (touched, flag) = non_structural_gate(&patch_text, request.patterns);
    if let Some(reason) = flag {
        record_flagged(
            request.flagged_store,
            SyncDirection::SandboxToHost,
            &reason,
            &patch_text,
        )?;
        emit_flagged(audit, SyncDirection::SandboxToHost, &reason);
        return Ok(SyncOutcome::Flagged {
            direction: SyncDirection::SandboxToHost,
            reason,
            patch: patch_text,
        });
    }

    let structurally_ok = patch::structurally_valid(runner, request.project_root, &patch_text)
        .map_err(|e| err(e.to_string()))?;
    if !structurally_ok {
        let reason = FlagReason::MalformedPatch(
            "`git apply --check` rejected this patch against the real project directory"
                .to_string(),
        );
        record_flagged(
            request.flagged_store,
            SyncDirection::SandboxToHost,
            &reason,
            &patch_text,
        )?;
        emit_flagged(audit, SyncDirection::SandboxToHost, &reason);
        return Ok(SyncOutcome::Flagged {
            direction: SyncDirection::SandboxToHost,
            reason,
            patch: patch_text,
        });
    }

    apply_patch_to_dir(runner, request.project_root, &patch_text)?;

    emit_applied(audit, SyncDirection::SandboxToHost, &touched);
    Ok(SyncOutcome::Applied {
        direction: SyncDirection::SandboxToHost,
        patch: patch_text,
        touched_paths: touched,
    })
}

/// Ref in the workspace repo marking the last commit already merged into
/// the host's real repo via [`merge_workspace_commits_to_host`] -- lets
/// repeated calls (a manual mid-session trigger, plus the automatic
/// end-of-session call) each replay only what's new since the previous
/// call, rather than re-merging or duplicating commits.
pub const HOST_MERGE_MARKER_REF: &str = "refs/habitat/last-merged-host";

/// What one [`merge_workspace_commits_to_host`] call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    /// The workspace repo had nothing new since the last call (or since
    /// its initial synthetic-seed commit, on the first call ever) -- no
    /// branch was created.
    NoOp,
    /// A new branch was created off `project_root`'s `HEAD` at call time,
    /// carrying these workspace commits (oldest first) replayed onto it
    /// via cherry-pick.
    Merged {
        branch: String,
        commits: Vec<String>,
    },
}

/// Replays every workspace-repo commit since the last successful call (or
/// since the workspace repo's initial synthetic-seed commit, on the very
/// first call) onto a brand-new `habitat/<timestamp>` branch off
/// `project_root`'s current `HEAD` -- via `git branch` + a throwaway `git
/// worktree` + `git cherry-pick`, never a `checkout` inside `project_root`
/// itself, so the operator's real working tree and index are left
/// completely untouched (unlike [`sync_sandbox_to_host`], which
/// deliberately does apply straight to the working tree every round --
/// this is a separate, coarser-grained mechanism for surfacing the
/// sandbox's actual commit history, not a replacement for that per-round
/// sync).
///
/// Safe to call any time the session's workspace repo is still alive --
/// a manual mid-session trigger and the automatic end-of-session call are
/// the exact same function, both cheap no-ops when there's nothing new to
/// bring in. Fails closed on any error partway through a non-empty merge:
/// the throwaway branch and worktree are removed and the marker ref is
/// left at its old value, so a failed attempt never leaves a half-built
/// branch behind or silently loses track of what still needs merging.
pub fn merge_workspace_commits_to_host<R: CommandRunner, A: AuditSink>(
    project_root: &Path,
    workspace_dir: &Path,
    runner: &R,
    audit: &A,
) -> Result<MergeOutcome, SyncError> {
    if !project_root.join(".git").exists() {
        // Not every host project is itself a git repo (`crate::gitseed`'s
        // `Synthetic` mode works either way) -- there's simply nowhere to
        // put a branch, which is a no-op here, not a session-ending
        // error.
        return Ok(MergeOutcome::NoOp);
    }
    let workspace_str = workspace_dir
        .to_str()
        .ok_or_else(|| err("workspace directory path is not valid UTF-8"))?;
    let project_str = project_root
        .to_str()
        .ok_or_else(|| err("project root path is not valid UTF-8"))?;

    let head = capture_git(runner, workspace_str, &["rev-parse", "HEAD"])?
        .trim()
        .to_string();
    let baseline = match capture_git(
        runner,
        workspace_str,
        &["rev-parse", "--verify", HOST_MERGE_MARKER_REF],
    ) {
        Ok(sha) => sha.trim().to_string(),
        Err(_) => capture_git(runner, workspace_str, &["rev-list", "--max-parents=0", "HEAD"])?
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string(),
    };

    if baseline == head {
        return Ok(MergeOutcome::NoOp);
    }

    let commits: Vec<String> = capture_git(
        runner,
        workspace_str,
        &["rev-list", "--reverse", &format!("{baseline}..{head}")],
    )?
    .lines()
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .map(str::to_string)
    .collect();

    if commits.is_empty() {
        // `baseline` is already the newest commit reachable in that
        // range -- nothing to replay, but advance the marker to `head` so
        // a future call doesn't keep re-walking the same empty range.
        set_merge_marker(runner, workspace_str, &head)?;
        return Ok(MergeOutcome::NoOp);
    }

    let host_head = capture_git(runner, project_str, &["rev-parse", "HEAD"])?
        .trim()
        .to_string();
    let branch = format!("habitat/{}", merge_branch_timestamp());

    capture_git(runner, project_str, &["branch", &branch, &host_head])?;
    capture_git(
        runner,
        project_str,
        &["fetch", "--no-tags", "--quiet", workspace_str, "HEAD"],
    )?;

    let worktree = merge_worktree_path();
    let worktree_str = worktree
        .to_str()
        .ok_or_else(|| err("merge worktree path is not valid UTF-8"))?;

    let result = (|| -> Result<(), SyncError> {
        capture_git(
            runner,
            project_str,
            &["worktree", "add", "--quiet", worktree_str, &branch],
        )?;
        for commit in &commits {
            if let Err(e) = run_git_with_identity(runner, worktree_str, &["cherry-pick", commit]) {
                let _ = capture_git(runner, worktree_str, &["cherry-pick", "--abort"]);
                return Err(err(format!(
                    "`git cherry-pick {commit}` failed replaying workspace commits onto {branch}: \
                     {e} -- aborted, {project_str}'s real branches left untouched"
                )));
            }
        }
        Ok(())
    })();

    let _ = capture_git(
        runner,
        project_str,
        &["worktree", "remove", "--force", worktree_str],
    );

    if let Err(e) = result {
        let _ = capture_git(runner, project_str, &["branch", "-D", &branch]);
        emit_merge_failed(audit, &e);
        return Err(e);
    }

    set_merge_marker(runner, workspace_str, &head)?;
    emit_merge_applied(audit, &branch, &commits);

    Ok(MergeOutcome::Merged { branch, commits })
}

fn set_merge_marker<R: CommandRunner>(
    runner: &R,
    workspace_str: &str,
    sha: &str,
) -> Result<(), SyncError> {
    capture_git(
        runner,
        workspace_str,
        &["update-ref", HOST_MERGE_MARKER_REF, sha],
    )
    .map(|_| ())
}

fn merge_branch_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string()
}

fn merge_worktree_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "habitat-merge-worktree-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

fn emit_merge_applied<A: AuditSink>(audit: &A, branch: &str, commits: &[String]) {
    let _ = audit.record(&AuditEvent::now(
        EventKind::GitMergeApplied,
        None,
        format!("branch {branch}: {} commit(s)", commits.len()),
    ));
}

fn emit_merge_failed<A: AuditSink>(audit: &A, error: &SyncError) {
    let _ = audit.record(&AuditEvent::now(
        EventKind::GitMergeFailed,
        None,
        error.to_string(),
    ));
}

fn capture_git<R: CommandRunner>(
    runner: &R,
    dir: &str,
    args: &[&str],
) -> Result<String, SyncError> {
    // See the matching comment in gitseed.rs::run_git: the bind-mounted
    // staging dir can appear host-side as owned by a UID other than ours,
    // which git's ownership check would otherwise refuse outright.
    let safe_directory = format!("safe.directory={dir}");
    let mut full_args = vec!["-c", safe_directory.as_str(), "-C", dir];
    full_args.extend_from_slice(args);
    let output = runner
        .run("git", &full_args)
        .map_err(|e| err(format!("could not run `git {}`: {e}", args.join(" "))))?;
    if !output.status.success() {
        return Err(err(format!(
            "`git {}` exited non-zero: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn scratch_dir_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "habitat-sync-scratch-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

/// Diffs `old_dir`'s current contents against `new_dir` via `git diff
/// --no-index`, read-only -- neither directory is touched, and this
/// works whether or not either side is itself a git repository (`git
/// diff --no-index` compares plain filesystem trees, not git objects).
/// This is the "validate before mutate" read: the caller decides whether
/// to apply the result to `old_dir` only after it passes the gate.
///
/// `--no-index` exits `1` (not `0`) whenever it finds any difference at
/// all -- that is the expected, successful "there's a diff" outcome
/// here, not a failure; only some other exit status means `git` itself
/// could not complete the comparison.
fn diff_no_index<R: CommandRunner>(
    runner: &R,
    old_dir: &Path,
    new_dir: &Path,
) -> Result<String, SyncError> {
    let old_abs = std::fs::canonicalize(old_dir)
        .map_err(|e| err(format!("could not resolve {}: {e}", old_dir.display())))?;
    let new_abs = std::fs::canonicalize(new_dir)
        .map_err(|e| err(format!("could not resolve {}: {e}", new_dir.display())))?;
    let old_str = old_abs
        .to_str()
        .ok_or_else(|| err("workspace directory path is not valid UTF-8"))?;
    let new_str = new_abs
        .to_str()
        .ok_or_else(|| err("scratch directory path is not valid UTF-8"))?;

    let output = runner
        .run("git", &["diff", "--no-index", "--", old_str, new_str])
        .map_err(|e| err(format!("could not run `git diff --no-index`: {e}")))?;
    match output.status.code() {
        Some(0) | Some(1) => {}
        _ => {
            return Err(err(format!(
                "`git diff --no-index` exited abnormally: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    let raw = String::from_utf8_lossy(&output.stdout).into_owned();
    Ok(strip_dot_git_blocks(&normalize_no_index_diff(
        &raw, old_str, new_str,
    )))
}

/// Drops every per-file block touching a `.git/...` path. `git diff
/// --no-index` has no concept of "this is a git repo" -- it walks
/// `old_dir` as a plain directory tree, `.git` included -- but `old_dir`
/// here is always the live workspace directory (which has a real `.git`)
/// and `new_dir` is always a `crate::staging::build_staging_dir` scratch
/// copy (which never has one, by that function's own contract). Left
/// unfiltered, every round would produce a patch that deletes the entire
/// workspace repository's `.git`. Must run after [`normalize_no_index_diff`]
/// so paths are already plain `a/<relpath> b/<relpath>`.
fn strip_dot_git_blocks(diff: &str) -> String {
    let mut out = String::with_capacity(diff.len());
    let mut skip_current_block = false;
    for line in diff.split_inclusive('\n') {
        if line.starts_with("diff --git ") {
            skip_current_block = diff_git_line_touches_dot_git(line);
        }
        if !skip_current_block {
            out.push_str(line);
        }
    }
    out
}

fn diff_git_line_touches_dot_git(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("diff --git a/") else {
        return false;
    };
    let Some(idx) = rest.find(" b/") else {
        return false;
    };
    let a_path = &rest[..idx];
    let b_path = rest[idx + 3..].trim_end();
    is_dot_git_path(a_path) || is_dot_git_path(b_path)
}

fn is_dot_git_path(path: &str) -> bool {
    path == ".git" || path.starts_with(".git/")
}

/// Undoes the absolute-path prefixes `git diff --no-index` bakes into its
/// `diff --git a/<...> b/<...>`/`--- a/<...>`/`+++ b/<...>` header lines
/// (`git` strips a leading `/` and prepends its own `a/`/`b/` prefix to
/// whichever path was given on the command line), so the result reads
/// like an ordinary in-repo diff: real repo-relative paths, appliable
/// with plain `git apply`'s default `-p1`, and correctly parsed by
/// [`patch::extract_touched_paths`] for the blocklist/content-ruleset
/// gate. Only rewrites recognized header lines -- never hunk-body
/// content, which can start with `+`/`-`/` ` followed by anything,
/// including text that happens to look like a path.
fn normalize_no_index_diff(raw: &str, old_dir: &str, new_dir: &str) -> String {
    let old_prefix = format!("a/{}/", old_dir.trim_start_matches('/'));
    let new_prefix = format!("b/{}/", new_dir.trim_start_matches('/'));
    let mut out = String::with_capacity(raw.len());
    for line in raw.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            out.push_str("diff --git ");
            out.push_str(&rest.replacen(&old_prefix, "a/", 1).replacen(&new_prefix, "b/", 1));
        } else if let Some(rest) = line.strip_prefix("--- ") {
            out.push_str("--- ");
            out.push_str(&rest.replacen(&old_prefix, "a/", 1));
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            out.push_str("+++ ");
            out.push_str(&rest.replacen(&new_prefix, "b/", 1));
        } else {
            out.push_str(line);
        }
    }
    out
}
