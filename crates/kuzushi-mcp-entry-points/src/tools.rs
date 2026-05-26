//! Read-only tools over `.kuzushi/entry-points.json`.
//!
//! Path resolved from `KUZUSHI_MCP_ENTRY_POINTS_ARTIFACT`.

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};

pub(crate) const ARTIFACT_ENV: &str = "KUZUSHI_MCP_ENTRY_POINTS_ARTIFACT";

pub(crate) fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
        .register(list_descriptor(), ListHandler)
        .register(by_framework_descriptor(), ByFrameworkHandler)
        .register(by_method_descriptor(), ByMethodHandler)
}

fn list_descriptor() -> Tool {
    Tool {
        name: "entry_points:list".to_string(),
        description: "Return every entry point recorded by `entry-points:extract`. Each entry carries kind, method, path, handler, framework, language, and location.".to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

fn by_framework_descriptor() -> Tool {
    Tool {
        name: "entry_points:by_framework".to_string(),
        description: "Filter entry points by framework name (e.g. axum, express, fastapi)."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["framework"],
            "properties": {
                "framework": {"type": "string"}
            }
        }),
    }
}

fn by_method_descriptor() -> Tool {
    Tool {
        name: "entry_points:by_method".to_string(),
        description: "Filter HTTP-route entry points by method (GET, POST, PUT, DELETE, ...)."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["method"],
            "properties": {
                "method": {"type": "string"}
            }
        }),
    }
}

struct ListHandler;
struct ByFrameworkHandler;
struct ByMethodHandler;

#[async_trait]
impl ToolHandler for ListHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        load_artifact()
    }
}

#[async_trait]
impl ToolHandler for ByFrameworkHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let framework = require_string(&args, "framework")?;
        Ok(filter_entries(load_artifact()?, |entry| {
            entry.get("framework").and_then(Value::as_str) == Some(&framework)
        }))
    }
}

#[async_trait]
impl ToolHandler for ByMethodHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let method = require_string(&args, "method")?.to_uppercase();
        Ok(filter_entries(load_artifact()?, |entry| {
            entry
                .get("method")
                .and_then(Value::as_str)
                .map(|m| m.to_uppercase() == method)
                .unwrap_or(false)
        }))
    }
}

fn require_string(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .with_context(|| format!("required string argument `{key}` is missing"))
}

fn filter_entries(artifact: Value, predicate: impl Fn(&Value) -> bool) -> Value {
    let entries = artifact
        .get("entryPoints")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let filtered: Vec<Value> = entries
        .into_iter()
        .filter(|entry| predicate(entry))
        .collect();
    json!({
        "total": filtered.len(),
        "entryPoints": filtered,
    })
}

pub(crate) fn load_artifact() -> Result<Value> {
    let path = std::env::var(ARTIFACT_ENV).with_context(|| {
        format!(
            "{ARTIFACT_ENV} is unset — the bridge should set it to the absolute path of \
             .kuzushi/entry-points.json before attaching this MCP."
        )
    })?;
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("reading entry-points artifact at {path}"))?;
    serde_json::from_str(&body)
        .with_context(|| format!("parsing entry-points at {path}: expected valid JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn write_fixture(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("entry-points.json");
        std::fs::write(&path, body).unwrap();
        (tmp, path)
    }

    #[tokio::test]
    async fn list_returns_all_entries() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (_tmp, path) =
            write_fixture(r#"{"entryPoints":[{"kind":"http-route","method":"GET","path":"/x"}]}"#);
        std::env::set_var(ARTIFACT_ENV, &path);
        let value = ListHandler.call(json!({})).await.unwrap();
        assert_eq!(value["entryPoints"].as_array().unwrap().len(), 1);
        std::env::remove_var(ARTIFACT_ENV);
    }

    #[tokio::test]
    async fn by_method_is_case_insensitive() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (_tmp, path) = write_fixture(
            r#"{"entryPoints":[
                {"kind":"http-route","method":"get","path":"/a"},
                {"kind":"http-route","method":"POST","path":"/b"}
            ]}"#,
        );
        std::env::set_var(ARTIFACT_ENV, &path);
        let gets = ByMethodHandler
            .call(json!({"method": "GET"}))
            .await
            .unwrap();
        assert_eq!(gets["total"], 1);
        let posts = ByMethodHandler
            .call(json!({"method": "post"}))
            .await
            .unwrap();
        assert_eq!(posts["total"], 1);
        std::env::remove_var(ARTIFACT_ENV);
    }
}
