//! Read-only tools over the `x-ray/` directory artifacts.
//!
//! `KUZUSHI_MCP_X_RAY_ARTIFACT` points at `x-ray/x-ray.md`; sibling
//! files (`entry-points.md`, `invariants.md`, `architecture.svg`) are
//! resolved relative to that directory.

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{ReadRootCapability, Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};
use std::path::PathBuf;

pub(crate) const ARTIFACT_ENV: &str = "KUZUSHI_MCP_X_RAY_ARTIFACT";
const MAX_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;

pub(crate) fn build_registry() -> Result<ToolRegistry> {
    Ok(build_registry_with_capability(
        ReadRootCapability::from_environment()?,
    ))
}

fn build_registry_with_capability(read_capability: ReadRootCapability) -> ToolRegistry {
    ToolRegistry::new()
        .register(
            summary_descriptor(),
            SummaryHandler(read_capability.clone()),
        )
        .register(
            entry_points_descriptor(),
            EntryPointsHandler(read_capability.clone()),
        )
        .register(invariants_descriptor(), InvariantsHandler(read_capability))
}

fn summary_descriptor() -> Tool {
    Tool {
        name: "x_ray:summary".to_string(),
        description: "Return the contents of x-ray/x-ray.md (architecture summary in markdown)."
            .to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

fn entry_points_descriptor() -> Tool {
    Tool {
        name: "x_ray:entry_points".to_string(),
        description: "Return the contents of x-ray/entry-points.md (markdown listing of HTTP/RPC/job entry points).".to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

fn invariants_descriptor() -> Tool {
    Tool {
        name: "x_ray:invariants".to_string(),
        description: "Return the contents of x-ray/invariants.md (system invariants identified by the analysis).".to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

struct SummaryHandler(ReadRootCapability);
struct EntryPointsHandler(ReadRootCapability);
struct InvariantsHandler(ReadRootCapability);

#[async_trait]
impl ToolHandler for SummaryHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        read_sibling(&self.0, "x-ray.md")
    }
}

#[async_trait]
impl ToolHandler for EntryPointsHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        read_sibling(&self.0, "entry-points.md")
    }
}

#[async_trait]
impl ToolHandler for InvariantsHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        read_sibling(&self.0, "invariants.md")
    }
}

fn read_sibling(read_capability: &ReadRootCapability, filename: &str) -> Result<Value> {
    let primary = std::env::var(ARTIFACT_ENV).with_context(|| {
        format!(
            "{ARTIFACT_ENV} is unset — the bridge should set it to the absolute path of \
             x-ray/x-ray.md before attaching this MCP."
        )
    })?;
    let primary_path = PathBuf::from(&primary);
    let requested_dir = primary_path
        .parent()
        .with_context(|| format!("{ARTIFACT_ENV}={primary} has no parent directory"))?;
    let dir = read_capability.resolve(requested_dir)?;
    let path = dir.join(filename);
    let body = match read_capability.read_utf8(&path, MAX_ARTIFACT_BYTES) {
        Ok(body) => body,
        Err(error) if is_missing_file(&error) => {
            return Ok(json!({"present": false, "path": path.display().to_string()}));
        }
        Err(error) => return Err(error).context("reading x-ray artifact"),
    };
    Ok(json!({
        "present": true,
        "path": path.display().to_string(),
        "body": body,
    }))
}

fn is_missing_file(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn summary_returns_xray_markdown() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("x-ray");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("x-ray.md");
        std::fs::write(&path, "# Architecture").unwrap();
        std::env::set_var(ARTIFACT_ENV, &path);
        let value = SummaryHandler(ReadRootCapability::new([tmp.path().to_path_buf()]).unwrap())
            .call(json!({}))
            .await
            .unwrap();
        assert_eq!(value["present"], true);
        assert_eq!(value["body"], "# Architecture");
        std::env::remove_var(ARTIFACT_ENV);
    }

    #[tokio::test]
    async fn missing_sibling_returns_present_false() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("x-ray");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("x-ray.md");
        std::fs::write(&path, "# Architecture").unwrap();
        std::env::set_var(ARTIFACT_ENV, &path);
        let value = InvariantsHandler(ReadRootCapability::new([tmp.path().to_path_buf()]).unwrap())
            .call(json!({}))
            .await
            .unwrap();
        assert_eq!(value["present"], false);
        std::env::remove_var(ARTIFACT_ENV);
    }
}
