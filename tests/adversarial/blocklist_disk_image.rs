//! Phase 2's required adversarial test (`tmp/wip/implementation-plan.md`
//! exit gate): seeds a project with variants of every blocklisted file
//! pattern and confirms none of them are present anywhere on the
//! resulting disk image -- nor in the intermediate staging directory
//! that fed it -- by actually building a real disk image (via `mke2fs`)
//! and extracting its contents back out (via `debugfs`) to inspect, no
//! shortcuts through the staging directory alone.
//!
//! Unlike Phase 3/5's containment/egress adversarial tests, this one
//! needs no real KVM -- `git`/e2fsprogs are ordinary tooling available in
//! this dev container and in this project's CI, so it runs for real
//! here rather than being deferred to `tests/manual/`.

use habitat_policy::config::ProjectConfig;
use habitat_workspace::command_runner::SystemCommandRunner;
use habitat_workspace::diskimage;
use habitat_workspace::pipeline::{self, BuildRequest};
use std::fs;
use std::path::{Path, PathBuf};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "habitat-adversarial-blocklist-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

/// One representative variant per default blocklist pattern
/// (`policy/blocklist.txt`), each carrying a unique, greppable secret
/// value so the test can prove that exact byte sequence is absent from
/// the built artifacts -- a stronger check than "the filename is
/// missing" alone (e.g. a bug that flattened directories could still
/// drop the filename check while leaking the bytes under another name).
fn blocklisted_variants() -> Vec<(&'static str, &'static str)> {
    vec![
        (".env", "SECRET_TOKEN=aaaa1111"),
        ("nested/dir/.env", "SECRET_TOKEN=aaaa2222"),
        ("config.pem", "-----BEGIN SECRET-AAAA3333-----"),
        ("deep/nested/id_rsa", "PRIVATE-KEY-SECRET-AAAA4444"),
        ("deep/nested/id_rsa.pub", "PRIVATE-KEY-SECRET-AAAA5555"),
        (".aws/credentials", "aws_secret_access_key=AAAA6666"),
        (
            "some/path/.aws/credentials",
            "aws_secret_access_key=AAAA7777",
        ),
        ("credentials.json", "{\"key\":\"AAAA8888\"}"),
        ("service-account-prod.json", "{\"key\":\"AAAA9999\"}"),
        (".npmrc", "//registry.npmjs.org/:_authToken=AAAA0001"),
        (".git-credentials", "https://user:AAAA0002@example.com"),
    ]
}

fn safe_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("main.rs", "fn main() {}"),
        ("README.md", "# hello"),
        ("src/lib.rs", "pub fn x() {}"),
    ]
}

#[test]
fn blocklisted_variants_never_reach_the_disk_image_or_the_staging_artifact() {
    let project = temp_dir("project");
    for (path, contents) in blocklisted_variants() {
        write(&project.join(path), contents);
    }
    for (path, contents) in safe_files() {
        write(&project.join(path), contents);
    }

    let workdir = temp_dir("workdir");
    let staging_dir = workdir.join("staging");
    let image_path = workdir.join("session.img");

    let request = BuildRequest {
        project_root: &project,
        staging_dir: staging_dir.clone(),
        image_path: image_path.clone(),
        image_size_mb: 32,
        // This test is about the filename blocklist specifically; content
        // scanning has its own adversarial coverage in
        // `content_scan_ruleset_tamper.rs` and its own exit gate in
        // `tests/unit/workspace/content_scan_exit_gate.rs`. Disabled here
        // so this test doesn't depend on `betterleaks` being installed
        // (it isn't ordinary tooling guaranteed present, unlike
        // `git`/e2fsprogs -- see `crates/install/src/checks.rs::betterleaks`).
        project_config: ProjectConfig {
            secrets_scan: habitat_policy::secrets_scan::SecretsScanConfig {
                content: habitat_policy::secrets_scan::Toggle::Disabled,
                ..Default::default()
            },
            ..Default::default()
        },
        content_ruleset_path: workdir.join("effective-betterleaks.toml"),
    };
    let outcome = pipeline::build(request, &SystemCommandRunner).expect("build should succeed");

    // 1. The intermediate staging artifact: walk it entirely and confirm
    //    none of the blocklisted secret values appear anywhere in it.
    let staging_contents = read_all_file_contents(&staging_dir);
    for (path, secret) in blocklisted_variants() {
        assert!(
            !staging_dir.join(path).exists(),
            "blocklisted file {path} must not exist in the staging directory"
        );
        assert!(
            !staging_contents.contains(secret),
            "secret value for {path} ({secret}) must not appear anywhere in the staging directory"
        );
    }
    for (path, _) in safe_files() {
        assert!(
            staging_dir.join(path).exists(),
            "non-blocklisted file {path} should have been staged"
        );
    }

    // 2. The actual disk image: extract it back out via debugfs (no
    //    mount, no loop device, no root) and repeat the same checks
    //    against what's really on the image, not just what fed it.
    let dump_dir = workdir.join("dump");
    diskimage::dump_image_contents(&image_path, &dump_dir, &SystemCommandRunner)
        .expect("dumping the built image should succeed");
    let image_contents = read_all_file_contents(&dump_dir);
    for (path, secret) in blocklisted_variants() {
        assert!(
            !dump_dir.join(path).exists(),
            "blocklisted file {path} must not exist on the built disk image"
        );
        assert!(
            !image_contents.contains(secret),
            "secret value for {path} ({secret}) must not appear anywhere on the built disk image"
        );
    }
    for (path, _) in safe_files() {
        assert!(
            dump_dir.join(path).exists(),
            "non-blocklisted file {path} should be present on the built disk image"
        );
    }

    // 3. Cross-check against the pipeline's own report: every blocklisted
    //    variant must show up as explicitly skipped, not merely absent by
    //    coincidence (e.g. because of an unrelated copy bug).
    for (path, _) in blocklisted_variants() {
        assert!(
            outcome
                .staging_report
                .skipped_blocklisted
                .contains(&path.to_string()),
            "{path} should be reported as skipped-blocklisted"
        );
    }

    fs::remove_dir_all(&project).unwrap();
    fs::remove_dir_all(&workdir).unwrap();
}

/// Concatenates every regular file's contents under `root` into one
/// string, for a simple "does this secret value appear anywhere" scan.
fn read_all_file_contents(root: &Path) -> String {
    let mut combined = String::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(contents) = fs::read_to_string(&path) {
                combined.push_str(&contents);
                combined.push('\n');
            }
        }
    }
    combined
}
