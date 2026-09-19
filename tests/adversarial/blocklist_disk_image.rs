//! Seeds a project with variants of every blocklisted file pattern and
//! confirms none of them are present anywhere in the built staging
//! directory. That directory *is*, byte-for-byte, what the guest sees --
//! bind-mounted directly at `/workspace`, never baked into a built image
//! (`docs/decisions/0005-storage-layer.md`'s Correction section) -- so
//! proving they're absent here is proving they're absent from the guest,
//! with no separate extraction step needed.

use habitat_policy::config::ProjectConfig;
use habitat_workspace::command_runner::SystemCommandRunner;
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

/// One variant per default blocklist pattern, each with a unique greppable
/// secret value so the test can prove the bytes are absent, not just the
/// filename (a directory-flattening bug could still leak bytes under
/// another name).
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
fn blocklisted_variants_never_reach_the_staging_directory() {
    let project = temp_dir("project");
    for (path, contents) in blocklisted_variants() {
        write(&project.join(path), contents);
    }
    for (path, contents) in safe_files() {
        write(&project.join(path), contents);
    }

    let workdir = temp_dir("workdir");
    let staging_dir = workdir.join("staging");

    let request = BuildRequest {
        project_root: &project,
        staging_dir: staging_dir.clone(),
        // Content scanning has its own coverage elsewhere; disabled here so
        // this doesn't depend on betterleaks being installed.
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

    // The staging directory *is* what the guest sees, bind-mounted
    // directly -- so this is the only place that needs checking.
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

    // Every variant must show up as explicitly skipped, not merely
    // absent by coincidence.
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

/// Concatenates every regular file's contents under `root` for a simple
/// "does this secret value appear anywhere" scan.
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
