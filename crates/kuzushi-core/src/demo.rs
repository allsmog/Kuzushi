use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

pub const OFFLINE_DEMO_TASKS: [&str; 2] = ["secret-scan", "iac-scan"];

/// Offline first-wow fixture used by both CLI and shell demo paths.
/// The fixture is recreated on each run so repeated demos stay deterministic.
pub fn prepare_demo_fixture() -> Result<PathBuf> {
    let demo_dir = std::env::temp_dir().join("kuzushi-demo");
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
}
