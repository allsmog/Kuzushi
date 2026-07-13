//! Read-only tools over `.kuzushi/threat-model.json` (STRIDE by default;
//! pass `KUZUSHI_MCP_THREAT_MODEL_ARTIFACT` pointing at the PASTA
//! sibling to serve that methodology instead).

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{ReadRootCapability, Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) const ARTIFACT_ENV: &str = "KUZUSHI_MCP_THREAT_MODEL_ARTIFACT";
const MAX_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;

pub(crate) fn build_registry() -> Result<ToolRegistry> {
    Ok(build_registry_with_capability(
        ReadRootCapability::from_environment()?,
    ))
}

fn build_registry_with_capability(read_capability: ReadRootCapability) -> ToolRegistry {
    ToolRegistry::new()
        .register(get_descriptor(), GetHandler(read_capability.clone()))
        .register(
            threats_descriptor(),
            ThreatsHandler(read_capability.clone()),
        )
        .register(elements_descriptor(), ElementsHandler(read_capability))
}

fn get_descriptor() -> Tool {
    Tool {
        name: "threat_model:get".to_string(),
        description: "Return the full threat-model artifact (methodology, elements, threats, scope, stories).".to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

fn threats_descriptor() -> Tool {
    Tool {
        name: "threat_model:threats".to_string(),
        description:
            "List threats with an optional severity filter (`critical`, `high`, `medium`, `low`)."
                .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "severity": {"type": "string"}
            }
        }),
    }
}

fn elements_descriptor() -> Tool {
    Tool {
        name: "threat_model:elements".to_string(),
        description:
            "List DFD elements (assets, trust boundaries, actors) recorded in the threat model."
                .to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

struct GetHandler(ReadRootCapability);
struct ThreatsHandler(ReadRootCapability);
struct ElementsHandler(ReadRootCapability);

#[async_trait]
impl ToolHandler for GetHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        load_artifact(&self.0)
    }
}

#[async_trait]
impl ToolHandler for ThreatsHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let severity = args
            .get("severity")
            .and_then(Value::as_str)
            .map(|s| s.to_ascii_lowercase());
        let artifact = load_artifact(&self.0)?;
        let threats = artifact
            .get("threats")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let filtered: Vec<Value> = match severity {
            Some(s) => threats
                .into_iter()
                .filter(|t| {
                    t.get("severity")
                        .and_then(Value::as_str)
                        .map(|x| x.to_ascii_lowercase() == s)
                        .unwrap_or(false)
                })
                .collect(),
            None => threats,
        };
        Ok(json!({"total": filtered.len(), "threats": filtered}))
    }
}

#[async_trait]
impl ToolHandler for ElementsHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        let artifact = load_artifact(&self.0)?;
        Ok(artifact.get("elements").cloned().unwrap_or(json!([])))
    }
}

pub(crate) fn load_artifact(read_capability: &ReadRootCapability) -> Result<Value> {
    let path = std::env::var(ARTIFACT_ENV).with_context(|| {
        format!(
            "{ARTIFACT_ENV} is unset — the bridge should set it to the absolute path of \
             .kuzushi/threat-model.json (or the PASTA sibling) before attaching this MCP."
        )
    })?;
    let body = read_capability
        .read_utf8(Path::new(&path), MAX_ARTIFACT_BYTES)
        .with_context(|| format!("reading threat-model artifact at {path}"))?;
    serde_json::from_str(&body)
        .with_context(|| format!("parsing threat-model at {path}: expected valid JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn severity_filter_lowercases_input() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("threat-model.json");
        std::fs::write(
            &path,
            r#"{"threats":[
                {"id":"t1","severity":"High"},
                {"id":"t2","severity":"Low"}
            ]}"#,
        )
        .unwrap();
        std::env::set_var(ARTIFACT_ENV, &path);
        let handler = ThreatsHandler(ReadRootCapability::new([tmp.path().to_path_buf()]).unwrap());
        let high = handler.call(json!({"severity": "HIGH"})).await.unwrap();
        assert_eq!(high["total"], 1);
        let all = handler.call(json!({})).await.unwrap();
        assert_eq!(all["total"], 2);
        std::env::remove_var(ARTIFACT_ENV);
    }
}
