//! joern MCP tool implementations.

use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::doctor::{probe_all, which, HealthSummary};
use kuzushi_mcp_common::tool::{Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};

use crate::queries;
use crate::server::{parse_repo, run_query};

const PROBES: &[(&str, &[&str])] = &[
    ("joern", &["--version"]),
    ("joern-parse", &["--version"]),
    ("java", &["-version"]),
];

pub async fn health_summary() -> HealthSummary {
    probe_all(PROBES).await
}

pub fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
        .register(
            Tool {
                name: "joern.health".into(),
                description: "Report whether joern, joern-parse, and a JVM are available."
                    .into(),
                input_schema: json!({"type": "object", "properties": {}}),
            },
            HealthTool,
        )
        .register(
            Tool {
                name: "joern.parse".into(),
                description: "Build or refresh a CPG for a repo. Persists `cpg.bin.zip` under `~/.kuzushi/index/joern/`."
                    .into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath"],
                    "properties": { "repoPath": {"type": "string"} }
                }),
            },
            ParseTool,
        )
        .register(
            Tool {
                name: "joern.query".into(),
                description: "Escape hatch: send a raw Scala query to a running `joern --server` and return the JSON result.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["scala"],
                    "properties": { "scala": {"type": "string"} }
                }),
            },
            QueryTool,
        )
        .register(
            Tool {
                name: "joern.callers_of".into(),
                description: "Return methods that call the named function. Backed by `cpg.method.name(...).caller.dedup.l`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["fn"],
                    "properties": { "fn": {"type": "string"} }
                }),
            },
            CallersOfTool,
        )
        .register(
            Tool {
                name: "joern.callees_of".into(),
                description: "Return methods called by the named function. Backed by `cpg.method.name(...).callee.dedup.l`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["fn"],
                    "properties": { "fn": {"type": "string"} }
                }),
            },
            CalleesOfTool,
        )
        .register(
            stub_descriptor(
                "joern.reaching_def",
                "Reaching definitions for a variable at a position (planned).",
            ),
            NotYetImplemented("joern.reaching_def"),
        )
        .register(
            stub_descriptor(
                "joern.taint_paths",
                "Taint paths from source to sink — wraps `reachableByFlows` (planned).",
            ),
            NotYetImplemented("joern.taint_paths"),
        )
        .register(
            stub_descriptor(
                "joern.unsafe_blocks",
                "Locate `unsafe { ... }` regions via the joern Rust frontend (planned).",
            ),
            NotYetImplemented("joern.unsafe_blocks"),
        )
        .register(
            stub_descriptor(
                "joern.ffi_boundaries",
                "Locate FFI boundaries — `extern \"C\"`, JNI, etc. (planned).",
            ),
            NotYetImplemented("joern.ffi_boundaries"),
        )
        .register(
            stub_descriptor(
                "joern.method_at",
                "Return the method enclosing a (file, line) position (planned).",
            ),
            NotYetImplemented("joern.method_at"),
        )
        .register(
            Tool {
                name: "joern.cpg_size".into(),
                description: "Counts: total nodes, methods, calls in the active CPG.".into(),
                input_schema: json!({"type": "object", "properties": {}}),
            },
            CpgSizeTool,
        )
}

fn stub_descriptor(name: &'static str, desc: &'static str) -> Tool {
    Tool {
        name: name.into(),
        description: desc.into(),
        input_schema: json!({"type": "object"}),
    }
}

struct HealthTool;
struct ParseTool;
struct QueryTool;
struct CallersOfTool;
struct CalleesOfTool;
struct CpgSizeTool;
struct NotYetImplemented(&'static str);

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

fn ensure_joern_available() -> Result<()> {
    if which("joern-parse").is_none() && which("joern").is_none() {
        anyhow::bail!(
            "BackendUnavailable: joern not on PATH. Install via https://docs.joern.io/installation."
        );
    }
    Ok(())
}

fn require_str<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}

#[async_trait]
impl ToolHandler for ParseTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let repo = std::path::PathBuf::from(require_str(&args, "repoPath")?);
        let handle = parse_repo(&repo).await?;
        Ok(serde_json::to_value(handle)?)
    }
}

#[async_trait]
impl ToolHandler for QueryTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let scala = require_str(&args, "scala")?.to_string();
        let raw = run_query(&scala).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({ "result": parsed }))
    }
}

#[async_trait]
impl ToolHandler for CallersOfTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let fn_name = require_str(&args, "fn")?.to_string();
        let raw = run_query(&queries::callers_of(&fn_name)).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({ "fn": fn_name, "callers": parsed }))
    }
}

#[async_trait]
impl ToolHandler for CalleesOfTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let fn_name = require_str(&args, "fn")?.to_string();
        let raw = run_query(&queries::callees_of(&fn_name)).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({ "fn": fn_name, "callees": parsed }))
    }
}

#[async_trait]
impl ToolHandler for CpgSizeTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let raw = run_query(queries::cpg_size_query()).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(parsed)
    }
}

#[async_trait]
impl ToolHandler for NotYetImplemented {
    async fn call(&self, _args: Value) -> Result<Value> {
        anyhow::bail!(
            "NotYetImplemented: tool `{}` is part of the planned joern MCP surface but is not yet wired.",
            self.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_includes_all_planned_tools() {
        let r = build_registry();
        for name in [
            "joern.health",
            "joern.parse",
            "joern.query",
            "joern.callers_of",
            "joern.callees_of",
            "joern.reaching_def",
            "joern.taint_paths",
            "joern.unsafe_blocks",
            "joern.ffi_boundaries",
            "joern.method_at",
            "joern.cpg_size",
        ] {
            assert!(r.contains(name), "missing tool: {name}");
        }
    }

    #[tokio::test]
    async fn callers_of_reports_backend_unavailable_when_joern_missing() {
        if which("joern-parse").is_some() || which("joern").is_some() {
            return;
        }
        let tool = CallersOfTool;
        let err = tool.call(json!({"fn": "main"})).await.unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn stubs_return_not_yet_implemented() {
        let tool = NotYetImplemented("joern.taint_paths");
        let err = tool.call(json!({})).await.unwrap_err();
        assert!(err.to_string().starts_with("NotYetImplemented:"));
    }
}
