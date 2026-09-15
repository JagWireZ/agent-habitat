//! Shared unified-diff/patch utilities used by both sync directions
//! (`crate::sync`): parsing which files a patch touches, and running the
//! structural "would this apply cleanly" check via `git apply --check`.
//! Deliberately independent of which direction a patch is travelling --
//! both directions run through exactly the same logic here
//! (`docs/plan.md` Section 2.2: "the same trusted patch mechanism ...
//! validated on arrival").

use crate::command_runner::CommandRunner;
use std::fmt;
use std::path::{Path, PathBuf};

/// The file this crate's content-scan snapshot governs
/// (`habitat_policy::secrets_scan`, `docs/decisions/0007-content-secrets-
/// scan-snapshot.md`). A sync patch touching a file with this basename is
/// routed through the flagged-for-review path regardless of its own
/// structural validity -- see `crate::sync::FlagReason::ContentRulesetMidSessionEdit`.
pub const CONTENT_RULESET_FILENAME: &str = "betterleaks.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchError {
    pub message: String,
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "patch: {}", self.message)
    }
}

impl std::error::Error for PatchError {}

fn err(message: impl Into<String>) -> PatchError {
    PatchError {
        message: message.into(),
    }
}

/// Parses the set of relative file paths a unified diff touches, read
/// from `diff --git a/<path> b/<path>` header lines -- exactly what
/// `git diff` and `git format-patch` always emit, regardless of what kind
/// of change (modify, add, delete, rename) each hunk represents. Order
/// preserved, de-duplicated. Deliberately hand-rolled rather than a
/// diff-parsing dependency, same reasoning as `habitat_policy::blocklist`'s
/// glob matcher: this is security-enforcement logic, kept small and fully
/// inspectable rather than delegated to a dependency's generality.
pub fn extract_touched_paths(patch: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git a/") {
            if let Some(idx) = rest.find(" b/") {
                let b_path = &rest[idx + 3..];
                if !b_path.is_empty() && !paths.iter().any(|p: &String| p == b_path) {
                    paths.push(b_path.to_string());
                }
            }
        }
    }
    paths
}

/// Whether any of `paths` is the content-scan ruleset file, matched by
/// basename (not full path) -- per
/// `docs/decisions/0007-content-secrets-scan-snapshot.md`, "the file's
/// mere presence in the patch is what matters here, regardless of what
/// changed", and regardless of which directory it lives in within the
/// project.
pub fn touches_content_ruleset_file(paths: &[String]) -> bool {
    paths.iter().any(|p| {
        Path::new(p).file_name().and_then(|n| n.to_str()) == Some(CONTENT_RULESET_FILENAME)
    })
}

/// The env var git honors to stop walking upward while searching for an
/// enclosing repository -- see [`git_apply_ceiling`]'s doc comment for
/// why every `git apply`/`git apply --check` call in this crate that
/// targets a plain (non-repo) directory must set it.
pub const GIT_CEILING_DIRECTORIES_VAR: &str = "GIT_CEILING_DIRECTORIES";

/// **Real-hardware-confirmed bug this works around:** `git apply`
/// silently no-ops a *new file* hunk -- printing `Skipped patch
/// '<file>'` to stderr but still exiting `0` -- whenever the `-C
/// <target>` directory is a *subdirectory* of some other git repository
/// discovered by walking upward from it, rather than that repository's
/// own toplevel. This has nothing to do with `.gitignore` content
/// (reproduced with zero ignore rules present); it depends purely on
/// `target` being a subdirectory of a discovered repo vs. being a repo's
/// own root vs. having no enclosing repo at all -- only the latter two
/// apply cleanly.
///
/// `crate::sync`'s `project_root` is deliberately never a git repository
/// of its own (Phase 2's plain, blocklist-filtered project tree), so
/// every `git apply -C project_root` call is exposed to this the moment
/// `project_root` happens to sit inside *any* unrelated enclosing repo.
/// `tests/manual/validate-sync.sh` hit this directly (`project_root`
/// lives nested under this very repo's own `tmp/`, discovered as the
/// enclosing repo); a real user's project layout is not guaranteed to
/// avoid it either. `mirror_dir` is unaffected -- it has its own `.git`,
/// so git resolves it as its own toplevel, not a subdirectory of
/// anything else.
///
/// The fix: point `GIT_CEILING_DIRECTORIES` at `target`'s own parent
/// before invoking `git apply`. `target` itself is always checked first
/// regardless of the ceiling, so this is a no-op for a directory that
/// already *is* a repo's own toplevel (`mirror_dir`), and the actual fix
/// for one that isn't (`project_root`) -- git's upward search now stops
/// at the boundary instead of continuing on to discover an unrelated
/// repo.
///
/// Returns the ceiling path as a UTF-8 string ready to hand to
/// [`CommandRunner::run_with_env`] under [`GIT_CEILING_DIRECTORIES_VAR`].
/// Errors rather than silently proceeding unprotected if `target` has no
/// parent directory, or if the parent isn't valid UTF-8 -- an
/// unprotected `git apply` call would silently reproduce the exact bug
/// this exists to prevent, which is worse than failing loudly here.
pub fn git_apply_ceiling(target: &Path) -> Result<String, PatchError> {
    let parent = target.parent().ok_or_else(|| {
        err(format!(
            "cannot compute a {GIT_CEILING_DIRECTORIES_VAR} boundary for {} -- it has no parent directory",
            target.display()
        ))
    })?;
    parent.to_str().map(str::to_string).ok_or_else(|| {
        err(format!(
            "{GIT_CEILING_DIRECTORIES_VAR} boundary path {} is not valid UTF-8",
            parent.display()
        ))
    })
}

/// Whether `git apply --check` accepts `patch` against the tree at
/// `target_dir` -- the real, authoritative structural-validity check,
/// run against whatever tree is the actual arrival point for this
/// direction (the guest's tree for host->sandbox, `project_root` for
/// sandbox->host; see `crate::sync`).
///
/// `Ok(true)`: structurally valid. `Ok(false)`: `git` ran and rejected the
/// patch as a real, well-formed refusal (corrupted patch, patch that
/// doesn't apply to the current tree state, etc.) -- this is a
/// classification, not an error, and callers route it to the
/// flagged-for-review state. `Err`: `git` itself could not be run at all
/// (missing binary, I/O failure writing the temp patch file) -- an
/// infrastructure failure, distinct from a bad patch.
pub fn structurally_valid<R: CommandRunner>(
    runner: &R,
    target_dir: &Path,
    patch: &str,
) -> Result<bool, PatchError> {
    let tmp = write_temp_patch_file(patch)?;
    let result = (|| {
        let target = target_dir
            .to_str()
            .ok_or_else(|| err("target directory path is not valid UTF-8"))?;
        let patch_path = tmp
            .to_str()
            .ok_or_else(|| err("temp patch file path is not valid UTF-8"))?;
        let ceiling = git_apply_ceiling(target_dir)?;
        let output = runner
            .run_with_env(
                &[(GIT_CEILING_DIRECTORIES_VAR, ceiling.as_str())],
                "git",
                &["-C", target, "apply", "--check", patch_path],
            )
            .map_err(|e| err(format!("could not run `git apply --check`: {e}")))?;
        Ok(output.status.success())
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Writes `patch` to a fresh temp file and returns its path -- shared by
/// [`structurally_valid`] and `crate::sync`'s actual-apply steps, since
/// both need the patch text as a real file on disk (either for `git
/// apply` directly, or to `podman cp` into a running guest).
pub fn write_temp_patch_file(patch: &str) -> Result<PathBuf, PatchError> {
    let path = std::env::temp_dir().join(format!(
        "habitat-sync-{}-{}.patch",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::write(&path, patch).map_err(|e| {
        err(format!(
            "could not write temp patch file {}: {e}",
            path.display()
        ))
    })?;
    Ok(path)
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        ^ (std::process::id() as u128)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::SystemCommandRunner;
    use std::fs;

    #[test]
    fn extract_touched_paths_reads_diff_git_headers() {
        let patch = "diff --git a/src/main.rs b/src/main.rs\n\
index 111..222 100644\n\
--- a/src/main.rs\n\
+++ b/src/main.rs\n\
@@ -1 +1 @@\n\
-old\n\
+new\n\
diff --git a/.env b/.env\n\
new file mode 100644\n\
--- /dev/null\n\
+++ b/.env\n\
@@ -0,0 +1 @@\n\
+SECRET=1\n";
        let paths = extract_touched_paths(patch);
        assert_eq!(paths, vec!["src/main.rs".to_string(), ".env".to_string()]);
    }

    #[test]
    fn extract_touched_paths_is_empty_for_a_patch_with_no_headers() {
        assert!(extract_touched_paths("not a real patch at all\njust noise\n").is_empty());
    }

    #[test]
    fn touches_content_ruleset_file_matches_by_basename_anywhere() {
        assert!(touches_content_ruleset_file(&[
            "betterleaks.toml".to_string()
        ]));
        assert!(touches_content_ruleset_file(&[
            "nested/dir/betterleaks.toml".to_string()
        ]));
        assert!(!touches_content_ruleset_file(&["src/main.rs".to_string()]));
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "habitat-workspace-patch-test-{name}-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // `git apply --check` is ordinary tooling, not KVM-dependent --
    // exercised for real here, same posture as `crate::gitseed`'s tests.
    #[test]
    fn structurally_valid_accepts_a_real_clean_patch() {
        let dir = temp_dir("clean");
        fs::write(dir.join("file.txt"), "hello\n").unwrap();
        let patch = "diff --git a/file.txt b/file.txt\n\
index 0000000..1111111 100644\n\
--- a/file.txt\n\
+++ b/file.txt\n\
@@ -1 +1 @@\n\
-hello\n\
+goodbye\n";
        assert!(structurally_valid(&SystemCommandRunner, &dir, patch).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn structurally_valid_rejects_a_corrupted_patch() {
        let dir = temp_dir("corrupted");
        fs::write(dir.join("file.txt"), "hello\n").unwrap();
        let corrupted = "this is not a unified diff at all\njust garbage text\n";
        assert!(!structurally_valid(&SystemCommandRunner, &dir, corrupted).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn structurally_valid_rejects_a_patch_whose_context_does_not_match() {
        let dir = temp_dir("mismatch");
        fs::write(dir.join("file.txt"), "totally different contents\n").unwrap();
        let patch = "diff --git a/file.txt b/file.txt\n\
index 0000000..1111111 100644\n\
--- a/file.txt\n\
+++ b/file.txt\n\
@@ -1 +1 @@\n\
-hello\n\
+goodbye\n";
        assert!(!structurally_valid(&SystemCommandRunner, &dir, patch).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }
}
