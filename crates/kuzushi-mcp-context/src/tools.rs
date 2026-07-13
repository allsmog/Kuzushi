//! Read-only tools over `.kuzushi/context-snapshot.json`.
//!
//! The snapshot path is resolved from the `KUZUSHI_MCP_CONTEXT_ARTIFACT`
//! environment variable (set by the bridge per-call, see
//! `kuzushi-openai/src/langgraph_runtime/bridge_process.rs`). Tools fail
//! with a clear error when the env var is missing — the artifact-aware
//! attachment probe in kuzushi-core is supposed to keep this server
//! from being attached unless the snapshot exists.

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{ReadRootCapability, Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) const ARTIFACT_ENV: &str = "KUZUSHI_MCP_CONTEXT_ARTIFACT";
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
            languages_descriptor(),
            LanguagesHandler(read_capability.clone()),
        )
        .register(
            attack_surface_nodes_descriptor(),
            AttackSurfaceHandler(read_capability.clone()),
        )
        .register(file_index_descriptor(), FileIndexHandler(read_capability))
}

fn get_descriptor() -> Tool {
    Tool {
        name: "context:get".to_string(),
        description: "Return the full repository context snapshot (target, timestamp, repoContext, repositoryInventory, attackSurfaceMap, fileIndex, appModel).".to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

fn languages_descriptor() -> Tool {
    Tool {
        name: "context:repo_languages".to_string(),
        description:
            "Return the languages and frameworks the context-build detected for this repository."
                .to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

fn attack_surface_nodes_descriptor() -> Tool {
    Tool {
        name: "context:attack_surface_nodes".to_string(),
        description: "List attack-surface nodes inferred from the workspace (HTTP routes, RPC endpoints, scheduled jobs, outbound clients, data stores). Optional `kind` filter narrows the result.".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "kind": {"type": "string", "description": "Optional node-kind filter (e.g. http-route, scheduled-job)."}
            }
        }),
    }
}

fn file_index_descriptor() -> Tool {
    Tool {
        name: "context:file_index".to_string(),
        description: "Return the file index recorded in the snapshot: `totalFiles`, `truncated`, and the sampled tree (up to `sampleLimit` paths).".to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

struct GetHandler(ReadRootCapability);
struct LanguagesHandler(ReadRootCapability);
struct AttackSurfaceHandler(ReadRootCapability);
struct FileIndexHandler(ReadRootCapability);

#[async_trait]
impl ToolHandler for GetHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        load_snapshot(&self.0)
    }
}

#[async_trait]
impl ToolHandler for LanguagesHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        let snapshot = load_snapshot(&self.0)?;
        let repo = snapshot.get("repoContext").cloned().unwrap_or(Value::Null);
        Ok(json!({
            "languages": repo.get("languages").cloned().unwrap_or(json!([])),
            "frameworks": repo.get("frameworks").cloned().unwrap_or(json!([])),
        }))
    }
}

#[async_trait]
impl ToolHandler for AttackSurfaceHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let snapshot = load_snapshot(&self.0)?;
        let kind_filter = args.get("kind").and_then(Value::as_str).map(str::to_string);
        let nodes = snapshot
            .get("attackSurfaceMap")
            .and_then(|map| map.get("nodes"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let filtered: Vec<Value> = match kind_filter {
            Some(kind) => nodes
                .into_iter()
                .filter(|node| node.get("kind").and_then(Value::as_str) == Some(kind.as_str()))
                .collect(),
            None => nodes,
        };
        Ok(json!({
            "total": filtered.len(),
            "nodes": filtered,
        }))
    }
}

#[async_trait]
impl ToolHandler for FileIndexHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        let snapshot = load_snapshot(&self.0)?;
        Ok(snapshot.get("fileIndex").cloned().unwrap_or(json!({})))
    }
}

pub(crate) fn load_snapshot(read_capability: &ReadRootCapability) -> Result<Value> {
    let path = std::env::var(ARTIFACT_ENV).with_context(|| {
        format!(
            "{ARTIFACT_ENV} is unset — the bridge should set it to the absolute path of \
             .kuzushi/context-snapshot.json before attaching this MCP."
        )
    })?;
    let body = read_capability
        .read_utf8(Path::new(&path), MAX_ARTIFACT_BYTES)
        .with_context(|| format!("reading context snapshot at {path}"))?;
    serde_json::from_str(&body)
        .with_context(|| format!("parsing context snapshot at {path}: expected valid JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn capability(root: &tempfile::TempDir) -> ReadRootCapability {
        ReadRootCapability::new([root.path().to_path_buf()]).unwrap()
    }

    #[tokio::test]
    async fn get_returns_snapshot_when_artifact_present() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("context-snapshot.json");
        std::fs::write(
            &path,
            r#"{"target":"/x","repoContext":{"languages":["rust"]}}"#,
        )
        .unwrap();
        std::env::set_var(ARTIFACT_ENV, &path);
        let value = GetHandler(capability(&tmp)).call(json!({})).await.unwrap();
        assert_eq!(value["target"], "/x");
        std::env::remove_var(ARTIFACT_ENV);
    }

    #[tokio::test]
    async fn languages_extracts_languages_and_frameworks() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("context-snapshot.json");
        std::fs::write(
            &path,
            r#"{"repoContext":{"languages":["rust","typescript"],"frameworks":["axum"]}}"#,
        )
        .unwrap();
        std::env::set_var(ARTIFACT_ENV, &path);
        let value = LanguagesHandler(capability(&tmp))
            .call(json!({}))
            .await
            .unwrap();
        assert_eq!(value["languages"], json!(["rust", "typescript"]));
        assert_eq!(value["frameworks"], json!(["axum"]));
        std::env::remove_var(ARTIFACT_ENV);
    }

    #[tokio::test]
    async fn attack_surface_filters_by_kind() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("context-snapshot.json");
        std::fs::write(
            &path,
            r#"{"attackSurfaceMap":{"nodes":[
                {"kind":"http-route","path":"/x"},
                {"kind":"scheduled-job","name":"y"}
            ]}}"#,
        )
        .unwrap();
        std::env::set_var(ARTIFACT_ENV, &path);
        let handler = AttackSurfaceHandler(capability(&tmp));
        let all = handler.call(json!({})).await.unwrap();
        assert_eq!(all["total"], 2);
        let routes = handler.call(json!({"kind": "http-route"})).await.unwrap();
        assert_eq!(routes["total"], 1);
        std::env::remove_var(ARTIFACT_ENV);
    }

    #[tokio::test]
    async fn rejects_an_artifact_outside_the_read_roots() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "{}").unwrap();
        std::env::set_var(ARTIFACT_ENV, outside.path());

        let error = GetHandler(capability(&root))
            .call(json!({}))
            .await
            .unwrap_err();

        std::env::remove_var(ARTIFACT_ENV);
        assert!(format!("{error:#}").contains("outside the MCP read roots"));
    }
}
