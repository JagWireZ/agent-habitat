//! Phase 4: the two-point host<->sandbox sync mechanism
//! (`tmp/wip/implementation-plan.md`, `docs/plan.md` Section 2.2).
//!
//! Both directions go through the same shape:
//! 1. Detect whether anything changed at all -- if not, stop; nothing is
//!    generated, applied, or logged (`AGENTS.md` Section 2, invariant 1's
//!    "no noise" companion in `docs/plan.md`).
//! 2. Produce a patch (a real unified diff, `git diff`/`git format-patch`
//!    output -- never a hand-rolled format).
//! 3. Run it through the validation gate ([`patch::extract_touched_paths`],
//!    the blocklist re-check, the content-ruleset special case, and
//!    [`patch::structurally_valid`] against the real arrival tree) --
//!    a patch that fails any of these is [`SyncOutcome::Flagged`], never
//!    silently merged and never silently dropped (`AGENTS.md` Section 2,
//!    invariant 10).
//! 4. Only a clean patch is actually applied -- to the guest's tree for
//!    host->sandbox, to the real host working directory for
//!    sandbox->host (`AGENTS.md` Section 2, invariant 3: the applied
//!    patch, not the agent's transcript, is the authoritative change
//!    record).
//!
//! **The host-side mirror.** Comparing the host's current project tree
//! against "whatever the guest currently has" needs a stable baseline to
//! diff against on the host side, without reaching into the guest's disk
//! image directly. That baseline is `mirror_dir`: the very same staging
//! directory Phase 2's pipeline built and git-seeded
//! (`crate::pipeline::BuildRequest::staging_dir`) -- its git history is
//! kept advancing in lockstep with the guest's own repo, one commit per
//! successful sync in either direction, so it always reflects "the state
//! the guest and the host both last agreed on."
//!
//! **No live/continuous channel.** Every guest-side step here is one
//! discrete `podman exec`/`podman cp` invocation
//! (`crate::guest_exec::GuestExecRunner`) -- there is no long-lived
//! connection, watcher, or background process anywhere in this module
//! (`AGENTS.md` Section 2, invariant 1).
//!
//! **Never a real push.** No code path in this module ever runs `git
//! push`, sets a `remote`, or otherwise reaches the user's real remote --
//! grep this file and you will not find either word outside this comment
//! (`AGENTS.md` Section 2, invariant 4). `tests/adversarial/
//! sync_patch_validation.rs` pins this as an executable check, not just a
//! comment.

use crate::command_runner::CommandRunner;
use crate::gitseed::{run_git_with_identity, SYNTHETIC_AUTHOR_EMAIL, SYNTHETIC_AUTHOR_NAME};
use crate::guest_exec::GuestExecRunner;
use crate::patch;
use crate::staging;
use habitat_audit::{AuditEvent, AuditSink, EventKind};
use habitat_policy::blocklist;
use habitat_vm::session::SessionId;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Where, inside the guest, the workspace disk is mounted -- this
/// module's best current understanding, in the same "confirm or correct
/// on real hardware" position as `habitat_vm::launcher::
/// WORKSPACE_DISK_ANNOTATION`. `tests/manual/validate-sync.sh` is where
/// this gets confirmed (or corrected) against a real booted guest.
pub const GUEST_WORKSPACE_DIR: &str = "/workspace";

/// The commit message used for every sync-driven commit, on both the
/// mirror and the guest -- distinct from `crate::gitseed`'s initial-seed
/// message so the two are never confused when reading either side's
/// `git log`.
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

/// Why a patch was flagged for review instead of applied -- its own
/// distinct state, never collapsed into a generic error (`AGENTS.md`
/// Section 2, invariant 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagReason {
    /// `git apply --check` rejected the patch against the real arrival
    /// tree -- corrupted, malformed, or simply no longer applicable.
    MalformedPatch(String),
    /// The patch re-introduces a path the blocklist would have stripped
    /// on the original build -- a smuggling attempt, or a stale/buggy
    /// patch, either way never applied.
    BlocklistedPathReintroduced(Vec<String>),
    /// The patch touches the project's `betterleaks.toml` --
    /// `docs/decisions/0007-content-secrets-scan-snapshot.md`: routed
    /// here unconditionally, regardless of the patch's own structural
    /// validity or whether the file itself is otherwise blocklisted.
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

/// Persists a flagged patch for operator review -- its own distinct,
/// visible state, never silently dropped. Each flagged patch gets a
/// `<timestamp>-<direction>.patch` file (the raw patch text) and a
/// sibling `.reason.txt` (why it was flagged), under one directory.
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
/// the structural half ([`patch::structurally_valid`]) is run separately
/// by each direction against its own real arrival tree (see this module's
/// doc comment for why that can't be unified into one directory
/// parameter here).
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

fn commit_with_synthetic_identity<R: CommandRunner>(
    runner: &R,
    dir: &Path,
    message: &str,
) -> Result<(), SyncError> {
    let dir_str = dir
        .to_str()
        .ok_or_else(|| err("mirror directory path is not valid UTF-8"))?;
    run_git_with_identity(runner, dir_str, &["add", "-A"]).map_err(|e| err(e.to_string()))?;
    run_git_with_identity(
        runner,
        dir_str,
        &["commit", "--quiet", "--allow-empty", "-m", message],
    )
    .map_err(|e| err(e.to_string()))
}

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
        let output = runner
            .run("git", &["-C", dir_str, "apply", patch_path])
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
    /// The host-side mirror of "what the guest currently has" -- Phase
    /// 2's staging directory, kept alive and advancing for the life of
    /// the session (see this module's doc comment).
    pub mirror_dir: &'a Path,
    pub session_id: &'a SessionId,
    pub patterns: &'a [String],
    pub flagged_store: &'a FlaggedPatchStore,
}

/// Host->sandbox sync, run immediately before each prompt: detects
/// host-side changes since the last sync, re-filters through the
/// blocklist, produces a patch, and applies it inside the guest.
///
/// Takes two separate `CommandRunner`s -- `host_runner` for ordinary,
/// local `git` calls against the host-side mirror (always real tooling,
/// same posture as `crate::gitseed`), and `guest_runner` for the
/// `podman exec`/`podman cp` calls that reach the actual guest
/// (`crate::guest_exec::GuestExecRunner`). In production both are the
/// same `SystemCommandRunner`; kept distinct here (rather than one
/// shared runner) so tests can fake the guest side with a
/// `FakeCommandRunner` while still exercising real `git` on the host
/// side, without the two colliding on the same seam.
pub fn sync_host_to_sandbox<H: CommandRunner, G: CommandRunner, A: AuditSink>(
    request: &HostToSandboxRequest<'_>,
    host_runner: &H,
    guest_runner: &G,
    audit: &A,
) -> Result<SyncOutcome, SyncError> {
    refresh_mirror_from_project(request.project_root, request.mirror_dir, request.patterns)?;

    let mirror_str = request
        .mirror_dir
        .to_str()
        .ok_or_else(|| err("mirror directory path is not valid UTF-8"))?;
    run_git_with_identity(host_runner, mirror_str, &["add", "-A"])
        .map_err(|e| err(e.to_string()))?;
    let diff = capture_git(host_runner, mirror_str, &["diff", "--cached"])?;

    if diff.trim().is_empty() {
        // Nothing to sync -- unstage the (empty) add and stop. No guest
        // interaction happens at all for a true no-op.
        run_git_with_identity(host_runner, mirror_str, &["reset", "--quiet"])
            .map_err(|e| err(e.to_string()))?;
        return Ok(SyncOutcome::NoOp);
    }

    let (touched, flag) = non_structural_gate(&diff, request.patterns);
    if let Some(reason) = flag {
        run_git_with_identity(
            host_runner,
            mirror_str,
            &["reset", "--hard", "--quiet", "HEAD"],
        )
        .map_err(|e| err(e.to_string()))?;
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

    let guest = GuestExecRunner::new(guest_runner, request.session_id);
    match apply_patch_in_guest(&guest, GUEST_WORKSPACE_DIR, &diff)? {
        GuestApplyOutcome::Applied => {}
        GuestApplyOutcome::Rejected(detail) => {
            run_git_with_identity(
                host_runner,
                mirror_str,
                &["reset", "--hard", "--quiet", "HEAD"],
            )
            .map_err(|e| err(e.to_string()))?;
            let reason = FlagReason::MalformedPatch(detail);
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
    }

    commit_with_synthetic_identity(host_runner, request.mirror_dir, SYNC_COMMIT_MESSAGE)?;
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
    pub mirror_dir: &'a Path,
    pub session_id: &'a SessionId,
    pub patterns: &'a [String],
    pub flagged_store: &'a FlaggedPatchStore,
}

/// Sandbox->host sync, run immediately after each tool call: detects
/// guest-side changes, commits them inside the guest's repo, produces a
/// patch, and -- once validated -- applies it directly to the real host
/// working directory (never just to the mirror, and never a guest-side
/// push to any real remote).
/// Same two-runner split as [`sync_host_to_sandbox`]: `host_runner` for
/// real `git` calls against `project_root`/`mirror_dir`, `guest_runner`
/// for the `podman exec` calls that reach the guest.
pub fn sync_sandbox_to_host<H: CommandRunner, G: CommandRunner, A: AuditSink>(
    request: &SandboxToHostRequest<'_>,
    host_runner: &H,
    guest_runner: &G,
    audit: &A,
) -> Result<SyncOutcome, SyncError> {
    let guest = GuestExecRunner::new(guest_runner, request.session_id);

    let status = guest
        .exec("git", &["-C", GUEST_WORKSPACE_DIR, "status", "--porcelain"])
        .map_err(|e| err(format!("could not run guest `git status`: {e}")))?;
    if !status.status.success() {
        return Err(err(format!(
            "guest `git status` exited non-zero: {}",
            String::from_utf8_lossy(&status.stderr)
        )));
    }
    if status.stdout.is_empty() {
        return Ok(SyncOutcome::NoOp);
    }

    let identity_env: [(&str, &str); 4] = [
        ("GIT_AUTHOR_NAME", SYNTHETIC_AUTHOR_NAME),
        ("GIT_AUTHOR_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
        ("GIT_COMMITTER_NAME", SYNTHETIC_AUTHOR_NAME),
        ("GIT_COMMITTER_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
    ];
    guest_git_ok(
        &guest,
        &identity_env,
        &["-C", GUEST_WORKSPACE_DIR, "add", "-A"],
        "guest `git add`",
    )?;
    guest_git_ok(
        &guest,
        &identity_env,
        &[
            "-C",
            GUEST_WORKSPACE_DIR,
            "commit",
            "--quiet",
            "-m",
            SYNC_COMMIT_MESSAGE,
        ],
        "guest `git commit`",
    )?;

    let diff_output = guest
        .exec(
            "git",
            &["-C", GUEST_WORKSPACE_DIR, "diff", "HEAD~1", "HEAD"],
        )
        .map_err(|e| err(format!("could not run guest `git diff`: {e}")))?;
    if !diff_output.status.success() {
        return Err(err(format!(
            "guest `git diff HEAD~1 HEAD` exited non-zero: {}",
            String::from_utf8_lossy(&diff_output.stderr)
        )));
    }
    let patch_text = String::from_utf8_lossy(&diff_output.stdout).into_owned();

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

    let structurally_ok = patch::structurally_valid(host_runner, request.project_root, &patch_text)
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

    apply_patch_to_dir(host_runner, request.project_root, &patch_text)?;
    apply_patch_to_dir(host_runner, request.mirror_dir, &patch_text)?;
    commit_with_synthetic_identity(host_runner, request.mirror_dir, SYNC_COMMIT_MESSAGE)?;

    emit_applied(audit, SyncDirection::SandboxToHost, &touched);
    Ok(SyncOutcome::Applied {
        direction: SyncDirection::SandboxToHost,
        patch: patch_text,
        touched_paths: touched,
    })
}

fn guest_git_ok<R: CommandRunner>(
    guest: &GuestExecRunner<'_, R>,
    env: &[(&str, &str)],
    args: &[&str],
    what: &str,
) -> Result<(), SyncError> {
    let output = guest
        .exec_with_env(env, "git", args)
        .map_err(|e| err(format!("could not run {what}: {e}")))?;
    if !output.status.success() {
        return Err(err(format!(
            "{what} exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

enum GuestApplyOutcome {
    Applied,
    /// `git apply --check` rejected the patch, run for real inside the
    /// guest -- the true arrival point for this direction, not a host-
    /// side proxy for it.
    Rejected(String),
}

/// Copies `patch_text` into the guest and applies it: `--check` first
/// (the real structural-validity check for this direction, run against
/// the actual guest tree rather than any host-side stand-in for it),
/// then the real apply only if that check passes.
fn apply_patch_in_guest<R: CommandRunner>(
    guest: &GuestExecRunner<'_, R>,
    guest_workdir: &str,
    patch_text: &str,
) -> Result<GuestApplyOutcome, SyncError> {
    let tmp = patch::write_temp_patch_file(patch_text).map_err(|e| err(e.to_string()))?;
    let result = (|| {
        let host_path = tmp
            .to_str()
            .ok_or_else(|| err("temp patch path is not valid UTF-8"))?;
        let guest_path = format!(
            "/tmp/habitat-sync-{}.patch",
            tmp.file_name().and_then(|n| n.to_str()).unwrap_or("patch")
        );

        let cp = guest
            .copy_in(host_path, &guest_path)
            .map_err(|e| err(format!("could not `podman cp` patch into guest: {e}")))?;
        if !cp.status.success() {
            return Err(err(format!(
                "`podman cp` into guest exited non-zero: {}",
                String::from_utf8_lossy(&cp.stderr)
            )));
        }

        let check = guest
            .exec(
                "git",
                &["-C", guest_workdir, "apply", "--check", &guest_path],
            )
            .map_err(|e| err(format!("could not run guest `git apply --check`: {e}")))?;
        if !check.status.success() {
            let _ = guest.exec("rm", &["-f", &guest_path]);
            return Ok(GuestApplyOutcome::Rejected(
                String::from_utf8_lossy(&check.stderr).into_owned(),
            ));
        }

        let apply = guest
            .exec("git", &["-C", guest_workdir, "apply", &guest_path])
            .map_err(|e| err(format!("could not run guest `git apply`: {e}")))?;
        let _ = guest.exec("rm", &["-f", &guest_path]);
        if !apply.status.success() {
            // Passed `--check` but the real apply still failed -- an
            // infrastructure problem (e.g. a race with a concurrent guest
            // change), not a validation classification, so this fails
            // closed as a hard error rather than a flagged patch.
            return Err(err(format!(
                "guest `git apply` exited non-zero after `--check` passed: {}",
                String::from_utf8_lossy(&apply.stderr)
            )));
        }

        guest_git_ok(
            guest,
            &[
                ("GIT_AUTHOR_NAME", SYNTHETIC_AUTHOR_NAME),
                ("GIT_AUTHOR_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
                ("GIT_COMMITTER_NAME", SYNTHETIC_AUTHOR_NAME),
                ("GIT_COMMITTER_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
            ],
            &["-C", guest_workdir, "add", "-A"],
            "guest `git add` (post-sync)",
        )?;
        guest_git_ok(
            guest,
            &[
                ("GIT_AUTHOR_NAME", SYNTHETIC_AUTHOR_NAME),
                ("GIT_AUTHOR_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
                ("GIT_COMMITTER_NAME", SYNTHETIC_AUTHOR_NAME),
                ("GIT_COMMITTER_EMAIL", SYNTHETIC_AUTHOR_EMAIL),
            ],
            &[
                "-C",
                guest_workdir,
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                SYNC_COMMIT_MESSAGE,
            ],
            "guest `git commit` (post-sync)",
        )?;

        Ok(GuestApplyOutcome::Applied)
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}

fn capture_git<R: CommandRunner>(
    runner: &R,
    dir: &str,
    args: &[&str],
) -> Result<String, SyncError> {
    let mut full_args = vec!["-C", dir];
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

/// Refreshes `mirror_dir`'s working tree (everything except `.git`) to
/// exactly match a fresh blocklist-filtered copy of `project_root` --
/// the same enforcement point the original disk build used
/// (`crate::staging::build_staging_dir`), reused here rather than
/// re-implemented, per this phase's dependency on Phase 2's filter.
fn refresh_mirror_from_project(
    project_root: &Path,
    mirror_dir: &Path,
    patterns: &[String],
) -> Result<(), SyncError> {
    let scratch = std::env::temp_dir().join(format!(
        "habitat-sync-scratch-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    staging::build_staging_dir(project_root, &scratch, patterns, None)
        .map_err(|e| err(format!("could not stage a fresh host snapshot: {e}")))?;
    let result = mirror_tree_contents(&scratch, mirror_dir)
        .map_err(|e| err(format!("could not refresh sync mirror: {e}")));
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

/// Makes every non-`.git` path under `dest` match `src` exactly: copies
/// everything from `src` into `dest`, then removes anything under `dest`
/// that isn't `.git` and has no counterpart in `src`.
fn mirror_tree_contents(src: &Path, dest: &Path) -> io::Result<()> {
    copy_all(src, src, dest)?;
    prune_stale(src, dest, dest)?;
    Ok(())
}

fn copy_all(root: &Path, dir: &Path, dest_root: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let dest = dest_root.join(relative);
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&dest)?;
            copy_all(root, &path, dest_root)?;
        } else {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&path, &dest)?;
        }
    }
    Ok(())
}

fn prune_stale(src_root: &Path, dir: &Path, dest_root: &Path) -> io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(dest_root).unwrap_or(&path);
        if relative.starts_with(".git") {
            continue;
        }
        let src_counterpart = src_root.join(relative);
        if entry.file_type()?.is_dir() {
            if src_counterpart.is_dir() {
                prune_stale(src_root, &path, dest_root)?;
            } else {
                std::fs::remove_dir_all(&path)?;
            }
        } else if !src_counterpart.is_file() {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}
