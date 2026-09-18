//! Assembles a staging directory into the session's disposable raw disk
//! image (`docs/decisions/0005-storage-layer.md`): a fixed-size file
//! formatted ext4 and populated directly via `mke2fs -d` -- no loop
//! device, no root, consistent with the rootless launch model. This
//! module only produces the file; attaching it as a `virtio-blk` device
//! happens elsewhere.
//!
//! Also provides [`dump_image_contents`] (`debugfs -R rdump`), which
//! extracts a populated image's contents without mounting -- used by the
//! adversarial test to confirm a blocklisted file is absent from the
//! actual image, not just the staging directory that fed it.

use crate::command_runner::CommandRunner;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskImageError {
    pub message: String,
}

impl std::fmt::Display for DiskImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "disk image: {}", self.message)
    }
}

impl std::error::Error for DiskImageError {}

fn err(message: impl Into<String>) -> DiskImageError {
    DiskImageError {
        message: message.into(),
    }
}

/// Builds `image_path` as a fresh, `size_mb`-megabyte raw disk image
/// containing exactly the contents of `staging_dir`. Never overwrites an
/// existing file, so a caller can't accidentally reuse a stale image.
pub fn assemble_disk_image<R: CommandRunner>(
    staging_dir: &Path,
    image_path: &Path,
    size_mb: u64,
    runner: &R,
) -> Result<(), DiskImageError> {
    if image_path.exists() {
        return Err(err(format!(
            "{} already exists -- refusing to overwrite a possibly stale disk image",
            image_path.display()
        )));
    }

    let file = std::fs::File::create(image_path)
        .map_err(|e| err(format!("could not create {}: {e}", image_path.display())))?;
    file.set_len(size_mb * 1024 * 1024)
        .map_err(|e| err(format!("could not size {}: {e}", image_path.display())))?;
    drop(file);

    let staging_str = staging_dir
        .to_str()
        .ok_or_else(|| err("staging directory path is not valid UTF-8"))?;
    let image_str = image_path
        .to_str()
        .ok_or_else(|| err("image path is not valid UTF-8"))?;

    let output = runner
        .run(
            "mke2fs",
            &["-q", "-F", "-t", "ext4", "-d", staging_str, image_str],
        )
        .map_err(|e| {
            err(format!(
                "could not run mke2fs (is e2fsprogs installed?): {e}"
            ))
        })?;

    if !output.status.success() {
        // Fail closed: don't leave a half-built image that a later step
        // could mistake for a good build.
        let _ = std::fs::remove_file(image_path);
        return Err(err(format!(
            "mke2fs exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Extracts everything inside `image_path` into `out_dir` (which must not
/// already exist) via `debugfs -R "rdump / <out_dir>"` -- read-only, no
/// mount, no root. Used only by adversarial verification, not the normal
/// build path.
pub fn dump_image_contents<R: CommandRunner>(
    image_path: &Path,
    out_dir: &Path,
    runner: &R,
) -> Result<(), DiskImageError> {
    if out_dir.exists() {
        return Err(err(format!(
            "{} already exists -- refusing to dump into it",
            out_dir.display()
        )));
    }
    std::fs::create_dir_all(out_dir)
        .map_err(|e| err(format!("could not create {}: {e}", out_dir.display())))?;

    let image_str = image_path
        .to_str()
        .ok_or_else(|| err("image path is not valid UTF-8"))?;
    let out_str = out_dir
        .to_str()
        .ok_or_else(|| err("output directory path is not valid UTF-8"))?;

    let output = runner
        .run("debugfs", &["-R", &format!("rdump / {out_str}"), image_str])
        .map_err(|e| {
            err(format!(
                "could not run debugfs (is e2fsprogs installed?): {e}"
            ))
        })?;

    if !output.status.success() {
        return Err(err(format!(
            "debugfs exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Convenience for tests/callers to assert an image was produced with
/// the expected size, without hand-rolling the check.
pub fn image_exists_and_is_sized(image_path: &Path, expected_mb: u64) -> io::Result<bool> {
    let metadata = std::fs::metadata(image_path)?;
    Ok(metadata.len() == expected_mb * 1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_runner::{testing::FakeCommandRunner, SystemCommandRunner};
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "habitat-workspace-diskimage-test-{name}-{}-{}",
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
    fn assemble_and_dump_round_trip_for_real() {
        let staging = temp_dir("staging");
        fs::write(staging.join("hello.txt"), "hello from staging").unwrap();
        fs::create_dir_all(staging.join("nested")).unwrap();
        fs::write(staging.join("nested/deep.txt"), "deep file").unwrap();

        let base = temp_dir("workdir");
        let image = base.join("session.img");
        assemble_disk_image(&staging, &image, 16, &SystemCommandRunner).unwrap();
        assert!(image_exists_and_is_sized(&image, 16).unwrap());

        let dump = base.join("dump");
        dump_image_contents(&image, &dump, &SystemCommandRunner).unwrap();
        assert_eq!(
            fs::read_to_string(dump.join("hello.txt")).unwrap(),
            "hello from staging"
        );
        assert_eq!(
            fs::read_to_string(dump.join("nested/deep.txt")).unwrap(),
            "deep file"
        );

        fs::remove_dir_all(&staging).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_an_existing_image() {
        let staging = temp_dir("staging-noop");
        let base = temp_dir("workdir-noop");
        let image = base.join("session.img");
        fs::write(&image, "already here").unwrap();

        let err = assemble_disk_image(&staging, &image, 16, &SystemCommandRunner).unwrap_err();
        assert!(err.message.contains("already exists"));
        assert_eq!(fs::read_to_string(&image).unwrap(), "already here");

        fs::remove_dir_all(&staging).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn mke2fs_failure_removes_the_half_built_image_and_fails_closed() {
        let staging = temp_dir("staging-fail");
        let base = temp_dir("workdir-fail");
        let image = base.join("session.img");
        let staging_str = staging.to_str().unwrap();
        let image_str = image.to_str().unwrap();
        let runner = FakeCommandRunner::default().with_failure(
            &format!("mke2fs -q -F -t ext4 -d {staging_str} {image_str}"),
            "mke2fs: some simulated failure",
        );

        let err = assemble_disk_image(&staging, &image, 8, &runner).unwrap_err();
        assert!(err.message.contains("simulated failure"));
        assert!(!image.exists(), "half-built image must not be left behind");

        fs::remove_dir_all(&staging).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }
}
