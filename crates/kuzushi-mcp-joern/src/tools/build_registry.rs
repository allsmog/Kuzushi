use anyhow::Result;
use kuzushi_mcp_common::{ReadRootCapability, Tool, ToolRegistry};
use serde_json::json;

use super::tool_types::{
    CalleesOfTool, CallersOfTool, CpgSizeTool, DefinitionsTool, FfiBoundariesTool, HealthTool,
    MethodAtTool, ParseTool, ReachingDefTool, TaintPathsTool, UnsafeBlocksTool,
};

pub fn build_registry() -> Result<ToolRegistry> {
    Ok(build_registry_with_capability(
        ReadRootCapability::from_environment()?,
    ))
}

pub(crate) fn build_registry_with_capability(read_capability: ReadRootCapability) -> ToolRegistry {
    ToolRegistry::new()
        .register(health_descriptor(), HealthTool)
        .register(parse_descriptor(), ParseTool::new(read_capability))
        .register(callers_descriptor(), CallersOfTool)
        .register(callees_descriptor(), CalleesOfTool)
        .register(definitions_descriptor(), DefinitionsTool)
        .register(reaching_def_descriptor(), ReachingDefTool)
        .register(taint_paths_descriptor(), TaintPathsTool)
        .register(unsafe_blocks_descriptor(), UnsafeBlocksTool)
        .register(ffi_boundaries_descriptor(), FfiBoundariesTool)
        .register(method_at_descriptor(), MethodAtTool)
        .register(cpg_size_descriptor(), CpgSizeTool)
}

fn definitions_descriptor() -> Tool {
    function_descriptor(
        "joern.definitions",
        "Return exact-name method definitions as typed symbol records.",
    )
}

fn health_descriptor() -> Tool {
    descriptor(
        "joern.health",
        "Report whether joern, joern-parse, and a JVM are available.",
        json!({"type": "object", "properties": {}}),
    )
}

fn parse_descriptor() -> Tool {
    descriptor(
        "joern.parse",
        "Build or refresh a CPG for a repo. Persists `cpg.bin.zip` under `~/.kuzushi/index/joern/`.",
        json!({
            "type": "object",
            "required": ["repoPath"],
            "properties": { "repoPath": {"type": "string"} }
        }),
    )
}

fn callers_descriptor() -> Tool {
    function_descriptor(
        "joern.callers_of",
        "Return methods that call the named function. Backed by `cpg.method.name(...).caller.dedup.l`.",
    )
}

fn callees_descriptor() -> Tool {
    function_descriptor(
        "joern.callees_of",
        "Return methods called by the named function. Backed by `cpg.method.name(...).callee.dedup.l`.",
    )
}

fn function_descriptor(name: &str, description: &str) -> Tool {
    descriptor(
        name,
        description,
        json!({
            "type": "object",
            "required": ["fn"],
            "properties": { "fn": {"type": "string"} }
        }),
    )
}

fn reaching_def_descriptor() -> Tool {
    descriptor(
        "joern.reaching_def",
        "Reaching definitions for a variable at a (file, line). Wraps `reachingDefIn`.",
        json!({
            "type": "object",
            "required": ["file", "line", "var"],
            "properties": {
                "file": {"type": "string"},
                "line": {"type": "integer", "minimum": 1},
                "var": {"type": "string"}
            }
        }),
    )
}

const TAINT_PATHS_DESCRIPTION: &str = "Taint paths from a source to a sink. The query unions two source traversals so the same regex finds both call-style sources (postgres `PG_GETARG_TEXT_PP`, JS `req.query`, etc.) and method-parameter sources (`argv` of `main`, request handler parameters): `(cpg.call.name(<source>) ++ cpg.method.name(<source>).parameter)`. The sink is a call-name regex. Returns an envelope: `{sourceCounts: {calls, methodParams}, sinkCount, maxCallDepth, flowCount, flows}` so the caller can tell \"the source pattern matched nothing\" from \"sources exist but no flow reaches the sink\". Both fields accept Java regex syntax. If both endpoints resolve but `flowCount=0`, retry once with `maxCallDepth: 24` (or `32` for very large CPGs).";

fn taint_paths_descriptor() -> Tool {
    descriptor(
        "joern.taint_paths",
        TAINT_PATHS_DESCRIPTION,
        taint_paths_schema(),
    )
}

fn taint_paths_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["source", "sink"],
        "properties": {
            "source": {"type": "string", "description": "Regex for taint sources. Matched against both `cpg.call.name(...)` and `cpg.method.name(...).parameter` so call and parameter sources work without selecting a CPG node kind."},
            "sink": {"type": "string", "description": "Call-name regex for taint sinks, e.g. `snprintf` or `snprintf|memcpy|strcpy`."},
            "maxPaths": {"type": "integer", "minimum": 1, "default": 50},
            "maxCallDepth": {"type": "integer", "minimum": 1, "maximum": 32, "default": 12, "description": "Joern interprocedural call-graph depth. Retry at 24 when sources and sinks resolve but no flow is found."}
        },
        "examples": [
            {"source": "PG_GETARG_TEXT_PP", "sink": "snprintf"},
            {"source": "PG_GETARG_TEXT_PP|PG_GETARG_CSTRING", "sink": "memcpy|strcpy|sprintf", "maxPaths": 10},
            {"source": "argv", "sink": "system|exec.*"},
            {"source": "GetConfigOption|namespace_search_path", "sink": "LookupFuncName|RangeVarGetRelid"},
            {"source": "PG_GETARG_TEXT_PP", "sink": "dlopen|load_external_function", "maxCallDepth": 24}
        ]
    })
}

fn unsafe_blocks_descriptor() -> Tool {
    descriptor(
        "joern.unsafe_blocks",
        "Locate `unsafe { ... }` regions via the joern Rust frontend. Optional `file` filter.",
        json!({"type": "object", "properties": {"file": {"type": "string"}}}),
    )
}

fn ffi_boundaries_descriptor() -> Tool {
    descriptor(
        "joern.ffi_boundaries",
        "Locate FFI boundaries: `extern \"C\"` decls, JNI calls, dlsym/dlopen.",
        json!({"type": "object", "properties": {}}),
    )
}

fn method_at_descriptor() -> Tool {
    descriptor(
        "joern.method_at",
        "Return the method enclosing a (file, line) coordinate.",
        json!({
            "type": "object",
            "required": ["file", "line"],
            "properties": {
                "file": {"type": "string"},
                "line": {"type": "integer", "minimum": 1}
            }
        }),
    )
}

fn cpg_size_descriptor() -> Tool {
    descriptor(
        "joern.cpg_size",
        "Counts: total nodes, methods, calls in the active CPG.",
        json!({"type": "object", "properties": {}}),
    )
}

fn descriptor(name: &str, description: &str, input_schema: serde_json::Value) -> Tool {
    Tool {
        name: name.into(),
        description: description.into(),
        input_schema,
    }
}
