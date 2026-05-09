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
                description: "Taint paths from a source to a sink. The query unions two source \
                              traversals so the same regex finds both call-style sources \
                              (postgres `PG_GETARG_TEXT_PP`, JS `req.query`, etc.) and \
                              method-parameter sources (`argv` of `main`, request handler \
                              parameters): `(cpg.call.name(<source>) ++ cpg.method.name(<source>).parameter)`. \
                              The sink is a call-name regex. Returns an envelope: \
                              `{sourceCounts: {calls, methodParams}, sinkCount, flowCount, flows}` \
                              so the caller can tell \"the source pattern matched nothing\" \
                              (sourceCounts.calls=0 and methodParams=0) from \"sources exist \
                              but no flow reaches the sink\" (counts > 0 and flowCount=0). \
                              Both fields accept Java regex syntax — alternation works \
                              (`PG_GETARG_TEXT_PP|PG_GETARG_CSTRING`), `.*` for substring, \
                              escaping for parens.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["source", "sink"],
                    "properties": {
                        "source": {"type": "string", "description": "Regex for taint sources. Matched against both `cpg.call.name(...)` and `cpg.method.name(...).parameter` so postgres macro-call sources (`PG_GETARG_TEXT_PP`) and method-parameter sources (`argv`) both work without the caller having to pick the CPG node kind."},
                        "sink": {"type": "string", "description": "Call-name regex for taint sinks, e.g. \"snprintf\" or \"snprintf|memcpy|strcpy\"."},
                        "maxPaths": {"type": "integer", "minimum": 1, "default": 50}
                    },
                    "examples": [
                        {"source": "PG_GETARG_TEXT_PP", "sink": "snprintf"},
                        {"source": "PG_GETARG_TEXT_PP|PG_GETARG_CSTRING", "sink": "memcpy|strcpy|sprintf", "maxPaths": 10},
                        {"source": "argv", "sink": "system|exec.*"},
                        {"source": "GetConfigOption|namespace_search_path", "sink": "LookupFuncName|RangeVarGetRelid"}
                    ]
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
