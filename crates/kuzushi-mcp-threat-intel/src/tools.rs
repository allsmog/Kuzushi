//! Read-only tools over `.kuzushi/threat-intel/candidates.json`.

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) const ARTIFACT_ENV: &str = "KUZUSHI_MCP_THREAT_INTEL_ARTIFACT";

pub(crate) fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
        .register(candidates_descriptor(), CandidatesHandler)
        .register(
            packages_by_ecosystem_descriptor(),
            PackagesByEcosystemHandler,
        )
}

fn candidates_descriptor() -> Tool {
    Tool {
        name: "threat_intel:candidates".to_string(),
        description: "Return the candidate CVE list and detected technologies/packages emitted by `threat-intel:discover`.".to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

fn packages_by_ecosystem_descriptor() -> Tool {
    Tool {
        name: "threat_intel:packages_by_ecosystem".to_string(),
        description: "Group detected packages by ecosystem (npm, cargo, pypi, go). Optional `ecosystem` filter narrows the result.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "ecosystem": {"type": "string"}
            }
        }),
    }
}

struct CandidatesHandler;
struct PackagesByEcosystemHandler;

#[async_trait]
impl ToolHandler for CandidatesHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        load_artifact()
    }
}

#[async_trait]
impl ToolHandler for PackagesByEcosystemHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let ecosystem = args
            .get("ecosystem")
            .and_then(Value::as_str)
            .map(str::to_string);
        let artifact = load_artifact()?;
        let packages = artifact
            .get("packages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut grouped: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for package in packages {
            let key = package
                .get("ecosystem")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            grouped.entry(key).or_default().push(package);
        }
        if let Some(filter) = ecosystem {
            let value = grouped.remove(&filter).unwrap_or_default();
            return Ok(json!({"ecosystem": filter, "total": value.len(), "packages": value}));
        }
        let summary: Vec<Value> = grouped
            .into_iter()
            .map(|(ecosystem, packages)| {
                json!({
                    "ecosystem": ecosystem,
                    "total": packages.len(),
                    "packages": packages,
                })
            })
            .collect();
        Ok(json!({"groups": summary}))
    }
}

pub(crate) fn load_artifact() -> Result<Value> {
    let path = std::env::var(ARTIFACT_ENV).with_context(|| {
        format!(
            "{ARTIFACT_ENV} is unset — the bridge should set it to the absolute path of \
             .kuzushi/threat-intel/candidates.json before attaching this MCP."
        )
    })?;
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("reading threat-intel artifact at {path}"))?;
    serde_json::from_str(&body)
        .with_context(|| format!("parsing threat-intel candidates at {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn packages_by_ecosystem_groups_then_filters() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("candidates.json");
        std::fs::write(
            &path,
            r#"{"packages":[
                {"ecosystem":"npm","name":"express"},
                {"ecosystem":"npm","name":"jest"},
                {"ecosystem":"cargo","name":"tokio"}
            ]}"#,
        )
        .unwrap();
        std::env::set_var(ARTIFACT_ENV, &path);
        let all = PackagesByEcosystemHandler.call(json!({})).await.unwrap();
        let groups = all["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        let npm = PackagesByEcosystemHandler
            .call(json!({"ecosystem": "npm"}))
            .await
            .unwrap();
        assert_eq!(npm["total"], 2);
        std::env::remove_var(ARTIFACT_ENV);
    }
}
