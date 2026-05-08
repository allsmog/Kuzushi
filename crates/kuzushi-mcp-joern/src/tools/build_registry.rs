use kuzushi_mcp_common::tool::{Tool, ToolRegistry};
use serde_json::json;

use super::tool_types::{
    CalleesOfTool, CallersOfTool, CpgSizeTool, FfiBoundariesTool, HealthTool, MethodAtTool,
    ParseTool, QueryTool, ReachingDefTool, TaintPathsTool, UnsafeBlocksTool,
};

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
