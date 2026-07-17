use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const OFFLINE_DEMO_TASKS: [&str; 2] = ["secret-scan", "iac-scan"];

/// Offline first-wow fixture used by both CLI and shell demo paths.
/// The fixture is recreated on each run so repeated demos stay deterministic.
pub fn prepare_demo_fixture() -> Result<PathBuf> {
    let demo_dir = demo_fixture_path();
    if demo_dir.exists() {
        fs::remove_dir_all(&demo_dir)
            .with_context(|| format!("could not reset {}", demo_dir.display()))?;
    }
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

/// Process-scoped demo location. Separate Kuzushi processes must not delete
/// each other's active fixture while recreating the deterministic demo.
pub fn demo_fixture_path() -> PathBuf {
    static DEMO_FIXTURE_PATH: OnceLock<PathBuf> = OnceLock::new();
    DEMO_FIXTURE_PATH
        .get_or_init(|| {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            std::env::temp_dir()
                .join(format!("kuzushi-demo-{}-{nonce}", std::process::id()))
                .join("kuzushi-demo")
        })
        .clone()
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
    fn demo_fixture_path_is_process_scoped_with_a_readable_leaf() {
        let path = demo_fixture_path();
        let parent = path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy();

        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("kuzushi-demo")
        );
        assert!(parent.contains(&std::process::id().to_string()), "{parent}");
        assert_eq!(demo_fixture_path(), path, "path stays stable in-process");
    }
}
