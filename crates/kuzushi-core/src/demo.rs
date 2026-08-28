use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const OFFLINE_DEMO_TASKS: [&str; 2] = ["secret-scan", "iac-scan"];

/// Offline first-wow fixture used by both CLI and shell demo paths.
///
/// Every preparation writes its own directory with identical contents, so a
/// new demo is deterministic without ever deleting a fixture. That matters
/// because activating a demo target starts background target-facts collection
/// and view hydration that keep reading and writing the fixture after the
/// demo that asked for it has moved on; recreating one shared directory raced
/// those writers and failed the preparation outright.
pub fn prepare_demo_fixture() -> Result<PathBuf> {
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    let demo_dir = demo_fixture_root()
        .join(NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed).to_string())
        .join("kuzushi-demo");
    fs::create_dir_all(&demo_dir)
        .with_context(|| format!("could not create {}", demo_dir.display()))?;
    fs::write(
        demo_dir.join("config.env"),
        "# production credentials accidentally committed\n\
         AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
         AWS_SECRET_ACCESS_KEY=wJalrXUtnFE/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
         GITHUB_TOKEN=ghp_x7rT9qLm2KvW8pYzN3jBdF5cH1aG6eQ4sU0i\n",
    )?;
    fs::write(
        demo_dir.join("Dockerfile"),
        "FROM node:latest\n\
         ADD https://example.com/setup.sh /setup.sh\n\
         COPY . .\n\
         RUN npm install\n\
         CMD [\"node\", \"server.js\"]\n",
    )?;
    Ok(demo_dir)
}

/// Process-scoped demo root. Separate Kuzushi processes must not disturb each
/// other's fixtures, so the root carries this process's id and start nonce.
fn demo_fixture_root() -> PathBuf {
    static DEMO_FIXTURE_ROOT: OnceLock<PathBuf> = OnceLock::new();
    DEMO_FIXTURE_ROOT
        .get_or_init(|| {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            std::env::temp_dir().join(format!("kuzushi-demo-{}-{nonce}", std::process::id()))
        })
        .clone()
}

/// True when `path` is one of this process's prepared offline demo fixtures.
pub fn is_demo_fixture_path(path: &Path) -> bool {
    match (path.canonicalize(), demo_fixture_root().canonicalize()) {
        (Ok(path), Ok(root)) => path.starts_with(root),
        _ => false,
    }
}

pub fn offline_demo_scan_input() -> Value {
    json!({
        "taskMode": "manual",
        "tasks": offline_demo_task_labels(),
        "disabledTasks": [],
        "triage": false,
        "verify": false,
        "autoPatch": false,
    })
}

pub fn offline_demo_task_labels() -> Vec<String> {
    OFFLINE_DEMO_TASKS
        .iter()
        .map(|task| (*task).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::{wants_sast_runtime, ModuleRegistry};

    #[test]
    fn offline_demo_input_stays_deterministic_and_runtime_free() {
        let registry = ModuleRegistry::with_v2_builtins();
        let input = registry
            .prepare_tool_input("sast:scan", offline_demo_scan_input(), None)
            .unwrap();

        assert_eq!(input["taskMode"], json!("manual"));
        assert_eq!(input["tasks"], json!(["secret-scan", "iac-scan"]));
        assert_eq!(input["triage"], json!(false));
        assert_eq!(input["verify"], json!(false));
        assert_eq!(input["autoPatch"], json!(false));
        assert!(!wants_sast_runtime(&input));
    }

    #[test]
    fn demo_fixture_root_is_process_scoped_and_stable() {
        let root = demo_fixture_root();
        let name = root.file_name().unwrap().to_string_lossy();

        assert!(name.contains(&std::process::id().to_string()), "{name}");
        assert_eq!(demo_fixture_root(), root, "root stays stable in-process");
    }

    #[test]
    fn each_preparation_owns_a_fresh_directory_with_a_readable_leaf() {
        let first = prepare_demo_fixture().unwrap();
        let second = prepare_demo_fixture().unwrap();

        assert_ne!(first, second, "a demo never reuses an earlier fixture");
        for fixture in [&first, &second] {
            assert_eq!(
                fixture.file_name().and_then(|name| name.to_str()),
                Some("kuzushi-demo")
            );
            assert!(fixture.join("config.env").is_file());
            assert!(fixture.join("Dockerfile").is_file());
            assert!(is_demo_fixture_path(fixture));
        }
    }

    #[test]
    fn paths_outside_the_demo_root_are_not_demo_fixtures() {
        let outside = tempfile::tempdir().unwrap();

        assert!(!is_demo_fixture_path(outside.path()));
        assert!(!is_demo_fixture_path(&demo_fixture_root().join("missing")));
    }
}
