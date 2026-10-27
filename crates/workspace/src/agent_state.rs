//! Copies each agent's auth and config files into the guest at launch and
//! its auth files back out during and after the session -- the replacement
//! for the persistent `~/.habitat/<agent>` bind mounts.
//!
//! **Why not a bind mount.** A mount is a live, always-on channel for the
//! whole session, exposes the host path's whole subtree, and let the guest
//! rewrite host files in place. Copying is discrete (one `scp` or `ssh` per
//! file, each over the per-session channel `guest_exec` already provides),
//! limited to the allowlisted manifest in `habitat_policy::agent_state`,
//! and -- for the direction that matters, guest to host -- the host reads
//! the bytes itself and decides whether to keep them. See
//! `docs/decisions/0011-agent-state-copy-in-out.md`.
//!
//! **Direction rules** (from the manifest's `role`):
//!
//! - `auth` files are copied in at launch and out again during and at the
//!   end of the session, because refresh tokens rotate while an agent runs
//!   and a first login may happen inside the guest.
//! - `config` files and directories are copied in only. A compromised
//!   session cannot plant a hook, MCP server, or instruction file that
//!   would load in every later session.
//!
//! **Copy-out treats the guest as hostile.** The file is read with
//! `head -c <cap+1> -- <path>` over `ssh` and the *host* does everything
//! else: size cap, UTF-8/JSON validation, refusing an empty file (a
//! half-written token must never replace a good one), refusing to write
//! through a symlink or onto a non-regular file, then a `0600` temp file
//! plus atomic rename. A missing guest file never deletes the host copy.
//! There is no `scp` from guest to host at all, so there is no
//! guest-influenced file-transfer protocol to trust.
//!
//! **Not covered** (documented limits, not oversights): a hostile guest
//! can still make `ssh` produce unbounded stdout, which the `CommandRunner`
//! seam buffers in memory -- the same exposure every other guest `exec` in
//! this crate already has (`head -c` bounds an honest guest, not a
//! malicious one). Fingerprints in the audit log are `SipHash` change
//! detectors, not cryptographic digests.
//!
//! **Concurrency.** Each agent's host directory carries a `.lock` file. The
//! session that holds the lock may copy out; a second concurrent session
//! for the same agent still gets its copy-in but never copies out, and says
//! so once in the audit log -- two sessions racing on one rotating refresh
//! token must not overwrite each other.

use crate::command_runner::CommandRunner;
use crate::guest_exec::GuestExecRunner;
use habitat_audit::{AuditEvent, AuditSink, EventKind};
use habitat_policy::agent_state::{self as manifest, Entry, Kind, Role};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Directory, relative to the operator's `$HOME`, holding every agent's
/// host-side copy: `~/.habitat/agents/<agent>/<home-relative-path>`.
pub const HOST_AGENTS_SUBDIR: &str = ".habitat/agents";

/// Largest auth file accepted coming back from the guest. `.claude.json`
/// accumulates per-project history and can reach a few MiB.
pub const MAX_AUTH_FILE_BYTES: usize = 8 * 1024 * 1024;
/// Largest single config file copied in.
pub const MAX_CONFIG_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Most files one config directory entry may contain.
pub const MAX_CONFIG_FILES_PER_DIR: usize = 200;
/// Deepest nesting inside one config directory entry.
pub const MAX_CONFIG_DIR_DEPTH: usize = 6;
/// Largest total size of one config directory entry.
pub const MAX_CONFIG_DIR_BYTES: u64 = 16 * 1024 * 1024;

/// What one copy pass did. `copied` and `rejected` hold manifest labels
/// (`agent:relative/path`); `rejected` also carries the reason.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CopyReport {
    pub copied: Vec<String>,
    pub rejected: Vec<(String, String)>,
}

impl CopyReport {
    pub fn is_clean(&self) -> bool {
        self.rejected.is_empty()
    }
}

struct AgentLock {
    agent: String,
    held: bool,
    // Kept open for the session's lifetime: dropping the file releases the
    // advisory lock.
    _file: File,
}

#[derive(Default)]
struct State {
    /// `agent:path` -> fingerprint of the content last known to be on both
    /// sides, so an unchanged file is never re-written or re-logged.
    fingerprints: HashMap<String, u64>,
    /// `agent:path` -> fingerprint of the last *rejected* guest content, so
    /// a persistently bad file does not log a rejection on every tick.
    last_rejected: HashMap<String, u64>,
    /// Agents whose "lock held elsewhere" notice has already been logged.
    warned_unlocked: HashSet<String>,
}

/// One session's view of agent state: which agents it may touch, where
/// their host-side copies live, and the per-agent locks.
pub struct AgentStateSession {
    agents_root: PathBuf,
    guest_home: String,
    entries: Vec<Entry>,
    locks: Vec<AgentLock>,
    state: Mutex<State>,
    /// Serializes whole copy passes (the shell session's background tick
    /// and its final pass must never interleave).
    op_lock: Mutex<()>,
}

fn other_err(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn fingerprint(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// Creates `path` (and parents) as `0700`, or tightens an existing
/// directory's mode to `0700`. Refuses a symlink unless
/// `allow_symlink` -- `~/.habitat` itself may legitimately be a symlink
/// (dotfile managers), nothing below it may be.
fn ensure_private_dir(path: &Path, allow_symlink: bool) -> io::Result<()> {
    let meta = if allow_symlink {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    match meta {
        Ok(m) => {
            if !m.is_dir() {
                return Err(other_err(format!(
                    "{} exists but is not a directory (symlinks are refused here)",
                    path.display()
                )));
            }
            if m.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new().recursive(true).mode(0o700).create(path)
        }
        Err(e) => Err(e),
    }
}

fn take_lock(agent_dir: &Path, agent: &str) -> io::Result<AgentLock> {
    let path = agent_dir.join(".lock");
    if let Ok(m) = fs::symlink_metadata(&path) {
        if m.file_type().is_symlink() {
            return Err(other_err(format!(
                "{} is a symlink; refusing to lock through it",
                path.display()
            )));
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    let held = match file.try_lock() {
        Ok(()) => true,
        Err(TryLockError::WouldBlock) => false,
        Err(TryLockError::Error(e)) => return Err(e),
    };
    Ok(AgentLock {
        agent: agent.to_string(),
        held,
        _file: file,
    })
}

/// Writes `bytes` to `dest` as a `0600` file via a temp file in the same
/// directory and an atomic rename. Refuses to replace anything that is not
/// a regular file (including a symlink), and creates missing parent
/// directories as `0700`.
fn write_private_atomic(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| other_err("destination has no parent directory"))?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    match fs::symlink_metadata(dest) {
        Ok(m) if !m.is_file() => {
            return Err(other_err(format!(
                "{} exists but is not a regular file (symlinks are refused)",
                dest.display()
            )))
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| other_err("destination has no usable file name"))?;
    let tmp = parent.join(format!(".{name}.habitat-tmp-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let written = f.write_all(bytes).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|_| fs::rename(&tmp, dest)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Content check for a file coming back from the guest.
fn validate_content(rel_path: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("empty file (a truncated write must not replace a good copy)".to_string());
    }
    if rel_path.ends_with(".json") {
        match serde_json::from_slice::<serde_json::Value>(bytes) {
            Ok(v) if v.is_object() => Ok(()),
            Ok(_) => Err("JSON is not an object".to_string()),
            Err(e) => Err(format!("not valid JSON: {e}")),
        }
    } else {
        std::str::from_utf8(bytes)
            .map(|_| ())
            .map_err(|_| "not valid UTF-8".to_string())
    }
}

/// Walks a host config directory before `scp -r` touches it. Fails on any
/// symlink, special file, odd file name, or limit breach -- `scp -r`
/// follows symlinks on the sending side, so this is what keeps a stray
/// link from pulling an arbitrary host file into the guest.
fn validate_tree(
    dir: &Path,
    depth: usize,
    files: &mut usize,
    bytes: &mut u64,
) -> Result<(), String> {
    if depth > MAX_CONFIG_DIR_DEPTH {
        return Err(format!(
            "{} is nested deeper than {MAX_CONFIG_DIR_DEPTH} levels",
            dir.display()
        ));
    }
    let rd = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(format!("{} has a non-UTF-8 name", path.display()));
        };
        if name.chars().any(|c| c.is_control()) {
            return Err(format!(
                "{} has a control character in its name",
                path.display()
            ));
        }
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(format!("{} is a symlink", path.display()));
        } else if ft.is_dir() {
            validate_tree(&path, depth + 1, files, bytes)?;
        } else if ft.is_file() {
            *files += 1;
            *bytes += meta.len();
            if *files > MAX_CONFIG_FILES_PER_DIR {
                return Err(format!(
                    "more than {MAX_CONFIG_FILES_PER_DIR} files under one config directory"
                ));
            }
            if meta.len() > MAX_CONFIG_FILE_BYTES {
                return Err(format!(
                    "{} is larger than {MAX_CONFIG_FILE_BYTES} bytes",
                    path.display()
                ));
            }
            if *bytes > MAX_CONFIG_DIR_BYTES {
                return Err(format!(
                    "config directory is larger than {MAX_CONFIG_DIR_BYTES} bytes in total"
                ));
            }
        } else {
            return Err(format!(
                "{} is not a regular file or directory",
                path.display()
            ));
        }
    }
    Ok(())
}

fn audit_event<A: AuditSink>(audit: &A, kind: EventKind, check: &str, message: String) {
    // Best-effort, like every other boundary event: a full disk must not
    // abort a session over its log line.
    let _ = audit.record(&AuditEvent::now(kind, Some(check), message));
}

fn parent_of(guest_path: &str) -> &str {
    guest_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("/")
}

impl AgentStateSession {
    /// Prepares one session's agent state: creates `~/.habitat`,
    /// `~/.habitat/agents`, and each named agent's directory as `0700`
    /// (tightening any that were looser), and takes (or fails to take) each
    /// agent's lock. `agents` are manifest ids (`claude`, `codex`,
    /// `opencode`); ids with no manifest entries are ignored.
    ///
    /// `home` is the operator's real `$HOME`, passed in rather than read
    /// here so this stays testable against a temporary directory.
    /// `guest_home` is the guest account's home (`/home/habitat`).
    pub fn open(home: &Path, agents: &[&str], guest_home: &str) -> io::Result<Self> {
        if !home.is_absolute() {
            return Err(other_err(format!(
                "home {} is not absolute",
                home.display()
            )));
        }
        if !guest_home.starts_with('/') || guest_home.ends_with('/') {
            return Err(other_err(format!(
                "guest home {guest_home:?} must be an absolute path without a trailing slash"
            )));
        }
        let entries = manifest::entries_for(agents);
        for e in &entries {
            manifest::validate_rel_path(&e.rel_path).map_err(other_err)?;
        }
        let habitat_dir = home.join(".habitat");
        let agents_root = home.join(HOST_AGENTS_SUBDIR);
        ensure_private_dir(&habitat_dir, true)?;
        ensure_private_dir(&agents_root, false)?;

        let mut seen: Vec<String> = Vec::new();
        for e in &entries {
            if !seen.contains(&e.agent) {
                seen.push(e.agent.clone());
            }
        }
        let mut locks = Vec::new();
        for agent in &seen {
            let dir = agents_root.join(agent);
            ensure_private_dir(&dir, false)?;
            locks.push(take_lock(&dir, agent)?);
        }
        Ok(AgentStateSession {
            agents_root,
            guest_home: guest_home.to_string(),
            entries,
            locks,
            state: Mutex::new(State::default()),
            op_lock: Mutex::new(()),
        })
    }

    /// The agent ids this session covers, in manifest order.
    pub fn agents(&self) -> Vec<&str> {
        self.locks.iter().map(|l| l.agent.as_str()).collect()
    }

    /// Whether this session holds `agent`'s lock (and so may copy out).
    pub fn holds_lock(&self, agent: &str) -> bool {
        self.locks.iter().any(|l| l.agent == agent && l.held)
    }

    /// Where `entry` lives on the host.
    pub fn host_path(&self, entry: &Entry) -> PathBuf {
        self.agents_root.join(&entry.agent).join(&entry.rel_path)
    }

    fn guest_path(&self, entry: &Entry) -> String {
        format!("{}/{}", self.guest_home, entry.rel_path)
    }

    fn label(entry: &Entry) -> String {
        format!("{}:{}", entry.agent, entry.rel_path)
    }

    fn reject<A: AuditSink>(
        audit: &A,
        report: &mut CopyReport,
        check: &str,
        entry: &Entry,
        reason: String,
    ) {
        let label = Self::label(entry);
        audit_event(
            audit,
            EventKind::AgentStateRejected,
            check,
            format!(
                "agent={} path={} reason={reason}",
                entry.agent, entry.rel_path
            ),
        );
        report.rejected.push((label, reason));
    }

    /// Copies every entry whose host-side file exists into the guest. A
    /// missing host file is simply skipped (first run, or an agent never
    /// set up). A rejected or failed entry never aborts the others and
    /// never fails the session -- an agent that cannot authenticate is
    /// visible in the report and the audit log, not fatal.
    pub fn copy_in<R: CommandRunner, A: AuditSink>(
        &self,
        guest: &GuestExecRunner<'_, R>,
        audit: &A,
    ) -> CopyReport {
        let _guard = self.op_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut report = CopyReport::default();

        struct FilePlan<'e> {
            entry: &'e Entry,
            host: PathBuf,
            guest_path: String,
            fp: Option<u64>,
        }
        struct DirPlan<'e> {
            entry: &'e Entry,
            host: PathBuf,
            guest_parent: String,
        }
        let mut files: Vec<FilePlan<'_>> = Vec::new();
        let mut dirs: Vec<DirPlan<'_>> = Vec::new();
        let mut mkdirs: BTreeSet<String> = BTreeSet::new();

        for entry in &self.entries {
            let host = self.host_path(entry);
            let meta = match fs::symlink_metadata(&host) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => {
                    Self::reject(
                        audit,
                        &mut report,
                        "copy-in",
                        entry,
                        format!("cannot inspect host path: {e}"),
                    );
                    continue;
                }
            };
            if meta.file_type().is_symlink() {
                Self::reject(
                    audit,
                    &mut report,
                    "copy-in",
                    entry,
                    "host path is a symlink; refused".to_string(),
                );
                continue;
            }
            let guest_path = self.guest_path(entry);
            match entry.kind {
                Kind::File => {
                    if !meta.is_file() {
                        Self::reject(
                            audit,
                            &mut report,
                            "copy-in",
                            entry,
                            "host path is not a regular file".to_string(),
                        );
                        continue;
                    }
                    let limit = match entry.role {
                        Role::Auth => MAX_AUTH_FILE_BYTES as u64,
                        Role::Config => MAX_CONFIG_FILE_BYTES,
                    };
                    if meta.len() > limit {
                        Self::reject(
                            audit,
                            &mut report,
                            "copy-in",
                            entry,
                            format!("host file is larger than {limit} bytes"),
                        );
                        continue;
                    }
                    let fp = if entry.role == Role::Auth {
                        match fs::read(&host) {
                            Ok(bytes) => Some(fingerprint(&bytes)),
                            Err(e) => {
                                Self::reject(
                                    audit,
                                    &mut report,
                                    "copy-in",
                                    entry,
                                    format!("cannot read host file: {e}"),
                                );
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    mkdirs.insert(parent_of(&guest_path).to_string());
                    files.push(FilePlan {
                        entry,
                        host,
                        guest_path,
                        fp,
                    });
                }
                Kind::Dir => {
                    if !meta.is_dir() {
                        Self::reject(
                            audit,
                            &mut report,
                            "copy-in",
                            entry,
                            "host path is not a directory".to_string(),
                        );
                        continue;
                    }
                    let (mut n, mut total) = (0usize, 0u64);
                    if let Err(why) = validate_tree(&host, 0, &mut n, &mut total) {
                        Self::reject(audit, &mut report, "copy-in", entry, why);
                        continue;
                    }
                    let guest_parent = parent_of(&guest_path).to_string();
                    mkdirs.insert(guest_parent.clone());
                    dirs.push(DirPlan {
                        entry,
                        host,
                        guest_parent,
                    });
                }
            }
        }

        if files.is_empty() && dirs.is_empty() {
            return report;
        }

        // One round trip creates every destination parent.
        let mut mkdir_args: Vec<&str> = vec!["-p"];
        mkdir_args.extend(mkdirs.iter().map(String::as_str));
        let made = matches!(guest.exec("mkdir", &mkdir_args), Ok(o) if o.status.success());
        if !made {
            for f in &files {
                Self::reject(
                    audit,
                    &mut report,
                    "copy-in",
                    f.entry,
                    "could not create guest directories".to_string(),
                );
            }
            for d in &dirs {
                Self::reject(
                    audit,
                    &mut report,
                    "copy-in",
                    d.entry,
                    "could not create guest directories".to_string(),
                );
            }
            return report;
        }

        let mut auth_guest_paths: Vec<String> = Vec::new();
        for f in files {
            let Some(host_str) = f.host.to_str() else {
                Self::reject(
                    audit,
                    &mut report,
                    "copy-in",
                    f.entry,
                    "host path is not UTF-8".to_string(),
                );
                continue;
            };
            match guest.copy_in(host_str, &f.guest_path) {
                Ok(o) if o.status.success() => {
                    let label = Self::label(f.entry);
                    let fp_note = match f.fp {
                        Some(fp) => {
                            self.state
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .fingerprints
                                .insert(label.clone(), fp);
                            auth_guest_paths.push(f.guest_path.clone());
                            format!(" fp={fp:016x}")
                        }
                        None => String::new(),
                    };
                    audit_event(
                        audit,
                        EventKind::AgentStateCopiedIn,
                        "copy-in",
                        format!("agent={} path={}{fp_note}", f.entry.agent, f.entry.rel_path),
                    );
                    report.copied.push(label);
                }
                Ok(o) => Self::reject(
                    audit,
                    &mut report,
                    "copy-in",
                    f.entry,
                    format!("scp failed: {}", String::from_utf8_lossy(&o.stderr).trim()),
                ),
                Err(e) => Self::reject(
                    audit,
                    &mut report,
                    "copy-in",
                    f.entry,
                    format!("could not run scp: {e}"),
                ),
            }
        }
        for d in dirs {
            let Some(host_str) = d.host.to_str() else {
                Self::reject(
                    audit,
                    &mut report,
                    "copy-in",
                    d.entry,
                    "host path is not UTF-8".to_string(),
                );
                continue;
            };
            match guest.copy_in_dir(host_str, &d.guest_parent) {
                Ok(o) if o.status.success() => {
                    audit_event(
                        audit,
                        EventKind::AgentStateCopiedIn,
                        "copy-in",
                        format!(
                            "agent={} path={} (directory)",
                            d.entry.agent, d.entry.rel_path
                        ),
                    );
                    report.copied.push(Self::label(d.entry));
                }
                Ok(o) => Self::reject(
                    audit,
                    &mut report,
                    "copy-in",
                    d.entry,
                    format!(
                        "scp -r failed: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ),
                ),
                Err(e) => Self::reject(
                    audit,
                    &mut report,
                    "copy-in",
                    d.entry,
                    format!("could not run scp: {e}"),
                ),
            }
        }

        if !auth_guest_paths.is_empty() {
            let mut args: Vec<&str> = vec!["600"];
            args.extend(auth_guest_paths.iter().map(String::as_str));
            // Best-effort tightening: the guest has one user, so a failure
            // here is not a boundary problem.
            let _ = guest.exec("chmod", &args);
        }
        report
    }

    /// Pulls every `auth` file whose guest content changed back to the
    /// host. Safe to call repeatedly (an unchanged file costs one `ssh`
    /// and writes nothing). Never touches `config` entries, never deletes
    /// a host file, and does nothing for an agent whose lock this session
    /// does not hold.
    pub fn copy_out<R: CommandRunner, A: AuditSink>(
        &self,
        guest: &GuestExecRunner<'_, R>,
        audit: &A,
    ) -> CopyReport {
        let _guard = self.op_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut report = CopyReport::default();
        let cap = MAX_AUTH_FILE_BYTES + 1;
        let cap_arg = cap.to_string();

        for entry in self.entries.iter().filter(|e| e.role == Role::Auth) {
            if entry.kind != Kind::File {
                continue;
            }
            if !self.holds_lock(&entry.agent) {
                let first_notice = self
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .warned_unlocked
                    .insert(entry.agent.clone());
                if first_notice {
                    Self::reject(
                        audit,
                        &mut report,
                        "copy-out",
                        entry,
                        "another habitat session holds this agent's lock; not copying out"
                            .to_string(),
                    );
                }
                continue;
            }
            let label = Self::label(entry);
            let guest_path = self.guest_path(entry);
            let out = match guest.exec("head", &["-c", &cap_arg, "--", &guest_path]) {
                Ok(o) => o,
                Err(e) => {
                    Self::reject(
                        audit,
                        &mut report,
                        "copy-out",
                        entry,
                        format!("could not run ssh: {e}"),
                    );
                    continue;
                }
            };
            match out.status.code() {
                Some(0) => {}
                // ssh itself reports a transport failure as 255.
                Some(255) | None => {
                    Self::reject(
                        audit,
                        &mut report,
                        "copy-out",
                        entry,
                        "ssh transport failure".to_string(),
                    );
                    continue;
                }
                // Anything else: the file is simply not there (never
                // logged in, or an agent that is not in use). A missing
                // guest file never deletes the host copy.
                Some(_) => continue,
            }
            let bytes = out.stdout;
            let fp = fingerprint(&bytes);

            {
                let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
                if st.fingerprints.get(&label) == Some(&fp) {
                    continue; // unchanged since it was copied in (or last out)
                }
            }

            let verdict = if bytes.len() > MAX_AUTH_FILE_BYTES {
                Err(format!("file is larger than {MAX_AUTH_FILE_BYTES} bytes"))
            } else {
                validate_content(&entry.rel_path, &bytes)
            };
            if let Err(why) = verdict {
                let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
                if st.last_rejected.get(&label) != Some(&fp) {
                    st.last_rejected.insert(label.clone(), fp);
                    drop(st);
                    Self::reject(audit, &mut report, "copy-out", entry, why);
                }
                continue;
            }

            let dest = self.host_path(entry);
            match write_private_atomic(&dest, &bytes) {
                Ok(()) => {
                    let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
                    st.fingerprints.insert(label.clone(), fp);
                    st.last_rejected.remove(&label);
                    drop(st);
                    audit_event(
                        audit,
                        EventKind::AgentStateCopiedOut,
                        "copy-out",
                        format!("agent={} path={} fp={fp:016x}", entry.agent, entry.rel_path),
                    );
                    report.copied.push(label);
                }
                Err(e) => Self::reject(
                    audit,
                    &mut report,
                    "copy-out",
                    entry,
                    format!("could not write host file: {e}"),
                ),
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_auth_content_must_be_a_nonempty_json_object() {
        assert!(validate_content(".x/auth.json", b"{\"a\":1}").is_ok());
        assert!(validate_content(".x/auth.json", b"").is_err());
        assert!(validate_content(".x/auth.json", b"[1,2]").is_err());
        assert!(validate_content(".x/auth.json", b"{\"a\":").is_err());
        assert!(validate_content(".x/auth.json", b"not json").is_err());
        // Deeply nested input must fail cleanly, not blow the stack.
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert!(validate_content(".x/auth.json", deep.as_bytes()).is_err());
    }

    #[test]
    fn non_json_content_must_be_utf8() {
        assert!(validate_content(".x/config.toml", b"a = 1\n").is_ok());
        assert!(validate_content(".x/config.toml", &[0xff, 0xfe, 0x00]).is_err());
    }

    #[test]
    fn fingerprint_distinguishes_content() {
        assert_eq!(fingerprint(b"abc"), fingerprint(b"abc"));
        assert_ne!(fingerprint(b"abc"), fingerprint(b"abd"));
    }

    #[test]
    fn parent_of_splits_on_the_last_slash() {
        assert_eq!(parent_of("/home/habitat/.claude.json"), "/home/habitat");
        assert_eq!(parent_of("/x"), "");
    }
}
