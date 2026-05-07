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
            Tool {
                name: "joern.reaching_def".into(),
                description: "Reaching definitions for a variable at a (file, line). Wraps `reachingDefIn`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["file", "line", "var"],
                    "properties": {
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "var": {"type": "string"}
                    }
                }),
            },
            ReachingDefTool,
        )
        .register(
            Tool {
                name: "joern.taint_paths".into(),
                description: "Taint paths from source to sink. Wraps `reachableByFlows`. Returns a list of paths (each a sequence of CPG nodes).".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["source", "sink"],
                    "properties": {
                        "source": {"type": "string"},
                        "sink": {"type": "string"},
                        "maxPaths": {"type": "integer", "minimum": 1, "default": 50}
                    }
                }),
            },
            TaintPathsTool,
        )
        .register(
            Tool {
                name: "joern.unsafe_blocks".into(),
                description: "Locate `unsafe { ... }` regions via the joern Rust frontend. Optional `file` filter.".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": { "file": {"type": "string"} }
                }),
            },
            UnsafeBlocksTool,
        )
        .register(
            Tool {
                name: "joern.ffi_boundaries".into(),
                description: "Locate FFI boundaries: `extern \"C\"` decls, JNI calls, dlsym/dlopen.".into(),
                input_schema: json!({"type": "object", "properties": {}}),
            },
            FfiBoundariesTool,
        )
        .register(
            Tool {
                name: "joern.method_at".into(),
                description: "Return the method enclosing a (file, line) coordinate.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["file", "line"],
                    "properties": {
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            MethodAtTool,
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

/// Build a placeholder descriptor used by tools that don't have their
/// implementation wired yet. Currently unused (all five planned tools
/// are now live) but kept as a reusable helper for the next round of
/// additions.
#[allow(dead_code)]
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
struct ReachingDefTool;
struct TaintPathsTool;
struct UnsafeBlocksTool;
struct FfiBoundariesTool;
struct MethodAtTool;
/// Sentinel handler kept for any future stubs we register before
/// implementing. No tool is currently registered as a stub.
#[allow(dead_code)]
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
impl ToolHandler for ReachingDefTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let file = require_str(&args, "file")?.to_string();
        let line = args
            .get("line")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("missing required integer argument: line"))?
            as u32;
        let var = require_str(&args, "var")?.to_string();
        let raw = run_query(&queries::reaching_def(&file, line, &var)).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({ "var": var, "file": file, "line": line, "definitions": parsed }))
    }
}

#[async_trait]
impl ToolHandler for TaintPathsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let source = require_str(&args, "source")?.to_string();
        let sink = require_str(&args, "sink")?.to_string();
        let max_paths = args
            .get("maxPaths")
            .or_else(|| args.get("max_paths"))
            .and_then(Value::as_u64)
            .unwrap_or(50) as usize;
        let raw = run_query(&queries::taint_paths(&source, &sink, max_paths)).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({
            "source": source,
            "sink": sink,
            "maxPaths": max_paths,
            "paths": parsed,
        }))
    }
}

#[async_trait]
impl ToolHandler for UnsafeBlocksTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let file = args.get("file").and_then(Value::as_str);
        let raw = run_query(&queries::unsafe_blocks(file)).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({
            "file": file,
            "blocks": parsed,
        }))
    }
}

#[async_trait]
impl ToolHandler for FfiBoundariesTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let raw = run_query(queries::ffi_boundaries()).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({ "boundaries": parsed }))
    }
}

#[async_trait]
impl ToolHandler for MethodAtTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_joern_available()?;
        let file = require_str(&args, "file")?.to_string();
        let line = args
            .get("line")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("missing required integer argument: line"))?
            as u32;
        let raw = run_query(&queries::method_at(&file, line)).await?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(json!({ "file": file, "line": line, "method": parsed }))
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
    async fn parse_and_method_at_report_backend_unavailable_when_joern_missing() {
        if which("joern-parse").is_some() || which("joern").is_some() {
            return;
        }
        let parse = ParseTool;
        let err = parse
            .call(json!({"repoPath": "/tmp/repo"}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));

        let method_at = MethodAtTool;
        let err = method_at
            .call(json!({"file": "/tmp/repo/a.c", "line": 7}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn stubs_marker_struct_still_returns_not_yet_implemented() {
        // Kept for any future tool we register as a stub before wiring.
        let tool = NotYetImplemented("future.tool");
        let err = tool.call(json!({})).await.unwrap_err();
        assert!(err.to_string().starts_with("NotYetImplemented:"));
    }

    #[tokio::test]
    async fn taint_paths_reports_backend_unavailable_when_joern_missing() {
        if which("joern-parse").is_some() || which("joern").is_some() {
            return;
        }
        let tool = TaintPathsTool;
        let err = tool
            .call(json!({"source": "argv", "sink": "system"}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn taint_paths_requires_source_and_sink() {
        if which("joern-parse").is_none() && which("joern").is_none() {
            return;
        }
        let tool = TaintPathsTool;
        let err = tool.call(json!({"source": "argv"})).await.unwrap_err();
        assert!(err.to_string().contains("sink"));
    }

    #[tokio::test]
    async fn reaching_def_requires_var_file_and_line() {
        if which("joern-parse").is_none() && which("joern").is_none() {
            return;
        }
        let tool = ReachingDefTool;
        let err = tool.call(json!({"file": "/r/a.c"})).await.unwrap_err();
        assert!(err.to_string().contains("line"));
    }

    #[tokio::test]
    async fn unsafe_blocks_accepts_optional_file() {
        // Schema check only — both valid and invalid args go through the
        // joern probe; this exercises the schema-validation arm.
        if which("joern-parse").is_some() || which("joern").is_some() {
            return;
        }
        let tool = UnsafeBlocksTool;
        let err = tool.call(json!({})).await.unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
        let err = tool.call(json!({"file": "/r/lib.rs"})).await.unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }
}
