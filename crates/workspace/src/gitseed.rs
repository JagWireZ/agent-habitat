//! Seeds the staging directory's git state, per the resolved
//! [`habitat_policy::git_history::GitHistoryMode`]:
//!
//! - `Synthetic` (default): a brand-new repo, seeded with the current
//!   staged files, committed under a fixed synthetic identity -- never
//!   the operator's own name/email (AGENTS.md Section 2 invariant 9).
//! - `RealHistoryReadOnly`: the project's real `.git` is copied into
//!   staging verbatim, then made read-only as defense in depth. The
//!   authoritative read-only guarantee is the guest-side mount option;
//!   this chmod pass is a best-effort mirror, not a substitute.
//!
//! Either way, this only ever touches `.git` -- `crate::staging` already
//! applied the blocklist to every other file.

use crate::command_runner::CommandRunner;
use std::io;
use std::path::Path;

/// A fixed, non-identifying author/committer used for every synthetic
/// commit, so the agent's own `git log` never surfaces anything personal.
/// `pub(crate)` so `crate::sync`'s mirror commits reuse this exact identity.
pub(crate) const SYNTHETIC_AUTHOR_NAME: &str = "Agent Habitat";
pub(crate) const SYNTHETIC_AUTHOR_EMAIL: &str = "sandbox@agent-habitat.invalid";
const SYNTHETIC_COMMIT_MESSAGE: &str = "Initial synthetic snapshot (Agent Habitat sandbox)";

/// Serializes every test that mutates the process-global
/// `GIT_AUTHOR_*`/`GIT_COMMITTER_*` env vars via [`run_git_with_identity`]
/// -- cargo runs a crate's tests in multiple threads by default, so
/// concurrent tests could interleave save/restore. Shared with
/// `crate::sync`'s tests rather than a second lock.
#[cfg(test)]
pub(crate) static GIT_IDENTITY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitSeedError {
    pub message: String,
}

impl std::fmt::Display for GitSeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "git seed: {}", self.message)
    }
}

impl std::error::Error for GitSeedError {}

fn err(message: impl Into<String>) -> GitSeedError {
    GitSeedError {
        message: message.into(),
    }
}

/// Initializes a fresh repo at `staging_dir` and commits its current
/// contents under the fixed synthetic identity above. Fails closed (no
/// partial repo left silently claiming to be seeded) if any `git`
/// invocation doesn't succeed.
pub fn seed_synthetic<R: CommandRunner>(
    staging_dir: &Path,
    runner: &R,
) -> Result<(), GitSeedError> {
    let dir = staging_dir
        .to_str()
        .ok_or_else(|| err("staging directory path is not valid UTF-8"))?;

    run_git(runner, dir, &["init", "--quiet"])?;
    // Git's default `gc.autoDetach` forks a background `git gc` after a
    // commit that crosses its loose-object threshold, which keeps
    // mutating `.git/objects` well after the triggering command returns.
    // `crate::sync`'s `git diff --no-index` walks this same directory as
    // plain files on every host->sandbox round -- confirmed (at
    // monorepo scale) to race that detached gc and fail with a spurious
    // "No such file or directory" on a loose object mid-repack. This
    // repo is disposable and re-seeded per session, so there is nothing
    // gc would usefully reclaim -- just turn it off.
    run_git(runner, dir, &["config", "gc.auto", "0"])?;
    run_git(runner, dir, &["add", "--all"])?;
    // --allow-empty: staging can legitimately end up empty (everything
    // filtered by the blocklist/content scanner) -- must not turn into a
    // confusing "nothing to commit" failure.
    run_git_with_identity(
        runner,
        dir,
        &[
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            SYNTHETIC_COMMIT_MESSAGE,
        ],
    )?;
    Ok(())
}

/// Copies the project's real `.git` directory into `staging_dir`
/// verbatim, then marks everything under it read-only (see module doc).
pub fn copy_real_history_read_only(
    project_root: &Path,
    staging_dir: &Path,
) -> Result<(), GitSeedError> {
    let src = project_root.join(".git");
    let dest = staging_dir.join(".git");
    if !src.is_dir() {
        return Err(err(format!(
            "git-history toggle is on, but {} does not exist -- nothing to share",
            src.display()
        )));
    }
    copy_dir_recursive(&src, &dest).map_err(|e| {
        err(format!(
            "failed copying {} into staging: {e}",
            src.display()
        ))
    })?;
    set_read_only_recursive(&dest)
        .map_err(|e| err(format!("failed marking {} read-only: {e}", dest.display())))?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if file_type.is_symlink() {
            continue; // skip rather than follow, same as crate::staging
        } else if file_type.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

fn set_read_only_recursive(path: &Path) -> io::Result<()> {
    let metadata = std::fs::metadata(path)?;
    let mut perms = metadata.permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(path, perms)?;
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_symlink() {
                set_read_only_recursive(&entry.path())?;
            }
        }
    }
    Ok(())
}

fn run_git<R: CommandRunner>(runner: &R, dir: &str, args: &[&str]) -> Result<(), GitSeedError> {
    // The staging dir is bind-mounted into the guest VM, whose user-namespace
    // UID mapping can leave it owned (from the host's point of view) by a
    // UID other than ours once the sandbox has written to it. Git's
    // ownership check would otherwise refuse every command here with
    // "dubious ownership" -- scope the trust to just this disposable,
    // per-session repo rather than mutating the operator's global git config.
    let safe_directory = format!("safe.directory={dir}");
    let mut full_args = vec!["-c", safe_directory.as_str(), "-C", dir];
    full_args.extend_from_slice(args);
    let output = runner
        .run("git", &full_args)
        .map_err(|e| err(format!("could not run `git {}`: {e}", args.join(" "))))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(err(format!(
            "`git {}` exited non-zero: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

/// Same as [`run_git`], but with the fixed synthetic author/committer
/// identity set via environment variables rather than global/repo git
/// config, so this never reads or mutates the operator's own
/// `~/.gitconfig`. `pub(crate)` so `crate::sync`'s mirror-side commits
/// reuse this mechanism.
pub(crate) fn run_git_with_identity<R: CommandRunner>(
    runner: &R,
    dir: &str,
    args: &[&str],
) -> Result<(), GitSeedError> {
    // CommandRunner shells out via std::process::Command, which reads the
    // calling process's env -- so identity is set via std::env for the
    // duration of this call, then restored.
    let restore = [
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
    ]
    .map(|k| (k, std::env::var(k).ok()));

    std::env::set_var("GIT_AUTHOR_NAME", SYNTHETIC_AUTHOR_NAME);
    std::env::set_var("GIT_AUTHOR_EMAIL", SYNTHETIC_AUTHOR_EMAIL);
    std::env::set_var("GIT_COMMITTER_NAME", SYNTHETIC_AUTHOR_NAME);
    std::env::set_var("GIT_COMMITTER_EMAIL", SYNTHETIC_AUTHOR_EMAIL);

    let result = run_git(runner, dir, args);

    for (key, previous) in restore {
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::SystemCommandRunner;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "habitat-workspace-gitseed-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn seed_synthetic_produces_a_repo_with_one_commit_under_the_synthetic_identity() {
        let _guard = GIT_IDENTITY_ENV_LOCK.lock().unwrap();
        let staging = temp_dir("synthetic");
        fs::write(staging.join("file.txt"), "hello").unwrap();

        seed_synthetic(&staging, &SystemCommandRunner).unwrap();

        assert!(staging.join(".git").is_dir());
        let log = std::process::Command::new("git")
            .args([
                "-C",
                staging.to_str().unwrap(),
                "log",
                "--format=%an <%ae> %s",
            ])
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&log.stdout);
        assert!(log.contains(SYNTHETIC_AUTHOR_NAME));
        assert!(log.contains(SYNTHETIC_AUTHOR_EMAIL));
        assert!(log.contains(SYNTHETIC_COMMIT_MESSAGE));
        assert_eq!(log.lines().count(), 1, "exactly one synthetic commit");

        fs::remove_dir_all(&staging).unwrap();
    }

    #[test]
    fn seed_synthetic_succeeds_over_an_empty_staging_directory() {
        let _guard = GIT_IDENTITY_ENV_LOCK.lock().unwrap();
        let staging = temp_dir("empty-staging");

        seed_synthetic(&staging, &SystemCommandRunner).unwrap();

        assert!(staging.join(".git").is_dir());
        fs::remove_dir_all(&staging).unwrap();
    }

    #[test]
    fn seed_synthetic_never_touches_the_calling_users_git_identity_afterwards() {
        let _guard = GIT_IDENTITY_ENV_LOCK.lock().unwrap();
        std::env::set_var("GIT_AUTHOR_NAME", "Should Not Leak");
        let staging = temp_dir("identity-restore");
        fs::write(staging.join("file.txt"), "hello").unwrap();

        seed_synthetic(&staging, &SystemCommandRunner).unwrap();

        assert_eq!(
            std::env::var("GIT_AUTHOR_NAME").unwrap(),
            "Should Not Leak",
            "the calling process's own env var must be restored, not left as the synthetic identity"
        );
        std::env::remove_var("GIT_AUTHOR_NAME");
        fs::remove_dir_all(&staging).unwrap();
    }

    #[test]
    fn copy_real_history_read_only_copies_and_locks_down_dot_git() {
        let project = temp_dir("real-history-src");
        std::process::Command::new("git")
            .args(["init", "--quiet", project.to_str().unwrap()])
            .output()
            .unwrap();
        fs::write(project.join("tracked.txt"), "v1").unwrap();

        let staging = temp_dir("real-history-staging");
        copy_real_history_read_only(&project, &staging).unwrap();

        let copied_head = staging.join(".git/HEAD");
        assert!(copied_head.exists());
        let perms = fs::metadata(&copied_head).unwrap().permissions();
        assert!(perms.readonly(), "copied .git contents must be read-only");

        fs::remove_dir_all(&project).unwrap();
        // Restore write permission so the temp dir can actually be
        // cleaned up.
        let mut dir_perms = fs::metadata(&staging).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        dir_perms.set_readonly(false);
        let _ = fs::set_permissions(&staging, dir_perms);
        let _ = fs::remove_dir_all(&staging);
    }

    #[test]
    fn copy_real_history_read_only_fails_closed_without_a_real_dot_git() {
        let project = temp_dir("no-git-here");
        let staging = temp_dir("no-git-here-staging");
        let err = copy_real_history_read_only(&project, &staging).unwrap_err();
        assert!(err.message.contains("does not exist"));
        fs::remove_dir_all(&project).unwrap();
        fs::remove_dir_all(&staging).unwrap();
    }
}
