//! Tool registry: descriptors + in-process handlers. Input schemas stay
//! byte-compatible with the retired `joern.*` tools where an equivalent
//! existed (`fn`, `file`/`line`/`var`, `source`/`sink`/`maxPaths`) so agent
//! prompts carry over; the names are `cpg.*` because the engine — and its
//! semantics (name-based summaries-first taint, no call-depth knob) — is
//! different, and run provenance should say so.

mod handlers;
mod taint_paths;

use kuzushi_mcp_common::{Tool, ToolRegistry};
use serde_json::json;

pub use handlers::health_summary;

pub fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
        .register(health_descriptor(), handlers::HealthTool)
        .register(parse_descriptor(), handlers::ParseTool)
        .register(callers_descriptor(), handlers::CallersOfTool)
        .register(callees_descriptor(), handlers::CalleesOfTool)
        .register(definitions_descriptor(), handlers::DefinitionsTool)
        .register(reaching_def_descriptor(), handlers::ReachingDefTool)
        .register(taint_paths_descriptor(), taint_paths::TaintPathsTool)
        .register(method_at_descriptor(), handlers::MethodAtTool)
        .register(cpg_size_descriptor(), handlers::CpgSizeTool)
        .register(slice_descriptor(), handlers::SliceTool)
}

fn health_descriptor() -> Tool {
    descriptor(
        "cpg.health",
        "Report engine status: target root, graph shape version, persisted per-language \
         graphs, and supported languages. The engine is compiled in — always available.",
        json!({"type": "object", "properties": {}}),
    )
}

fn parse_descriptor() -> Tool {
    descriptor(
        "cpg.parse",
        "Build or refresh the target's per-language graphs under .kuzushi/cpg-rs/. Usually \
         unnecessary: every query builds missing graphs implicitly in seconds.",
        json!({"type": "object", "properties": {}}),
    )
}

fn callers_descriptor() -> Tool {
    function_descriptor(
        "cpg.callers_of",
        "Methods containing calls to the function. Bare names use name matching and \
         reject ambiguous definitions; canonical selectors require resolved call targets.",
    )
}

fn callees_descriptor() -> Tool {
    function_descriptor(
        "cpg.callees_of",
        "Functions called inside the named method's body (exact name). Resolved callees \
         report their full name; unresolved externals report the bare call name.",
    )
}

fn definitions_descriptor() -> Tool {
    function_descriptor(
        "cpg.definitions",
        "Method definitions as typed records including a canonical selector, name, fullName, \
         signature, file, line and language. Returns all candidates for ambiguous names.",
    )
}

fn function_descriptor(name: &str, description: &str) -> Tool {
    descriptor(
        name,
        description,
        json!({
            "type": "object",
            "required": ["fn"],
            "properties": { "fn": {"type": "string", "description": "Unique name, full name, or canonical selector returned by cpg.definitions."} }
        }),
    )
}

fn reaching_def_descriptor() -> Tool {
    descriptor(
        "cpg.reaching_def",
        "Reaching definitions for a variable inside the method enclosing (file, line). \
         Requires an unambiguous AST node at that exact line; blank lines and gaps fail \
         rather than borrowing the preceding method. Returns intra-method definitions.",
        json!({
            "type": "object",
            "required": ["file", "line", "var"],
            "properties": {
                "file": {"type": "string"},
                "line": {"type": "integer", "minimum": 1, "maximum": 4294967295_u64},
                "var": {"type": "string"}
            }
        }),
    )
}

const TAINT_PATHS_DESCRIPTION: &str = "Interprocedural taint paths from a source to a sink over the in-process cpg-rs engine. `source`/`sink` accept a regex (or literal substring): matching call NAMES are harvested as the propagation vocabulary — the same regex finds call-style sources (postgres `PG_GETARG_TEXT_PP`, JS `req.query`) and method-name entry points (handler parameters). Propagation is summaries-first and name-based (recall-first; no SSA) with effectively unbounded call depth, so `maxCallDepth` is rejected because the engine cannot enforce it. Returns `{sourceCounts: {calls, methodParams}, sinkCount, flowCount, flows}` so \"the source pattern matched nothing\" is distinguishable from \"sources exist but no flow reaches the sink\". Flows carry witness steps with per-step code/line plus advisory guard/authz annotations.";

fn taint_paths_descriptor() -> Tool {
    descriptor(
        "cpg.taint_paths",
        TAINT_PATHS_DESCRIPTION,
        json!({
            "type": "object",
            "required": ["source", "sink"],
            "properties": {
                "source": {"type": "string", "description": "Regex (or literal) for taint sources; matched against call names, call code, and method names."},
                "sink": {"type": "string", "description": "Regex (or literal) for taint sinks, e.g. `snprintf` or `snprintf|memcpy|strcpy`."},
                "maxPaths": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
                "maxCallDepth": {"type": "integer", "minimum": 1, "description": "Unsupported by this engine; supplying this option fails before analysis."},
                "patternMode": {"type": "string", "enum": ["regex", "literal"], "default": "regex"}
            },
            "examples": [
                {"source": "PG_GETARG_TEXT_PP", "sink": "snprintf"},
                {"source": "req\\.query|request\\.args", "sink": "query|execute"},
                {"source": "argv", "sink": "system|exec.*"}
            ]
        }),
    )
}

fn method_at_descriptor() -> Tool {
    descriptor(
        "cpg.method_at",
        "The method enclosing a (file, line) coordinate. APPROXIMATE: the graph stores \
         method start lines only, so a line after a file's last method maps to that method.",
        json!({
            "type": "object",
            "required": ["file", "line"],
            "properties": {
                "file": {"type": "string"},
                "line": {"type": "integer", "minimum": 1, "maximum": 4294967295_u64}
            }
        }),
    )
}

fn cpg_size_descriptor() -> Tool {
    descriptor(
        "cpg.cpg_size",
        "Per-language graph counts: nodes, methods, calls, function summaries.",
        json!({"type": "object", "properties": {}}),
    )
}

fn slice_descriptor() -> Tool {
    descriptor(
        "cpg.slice",
        "Backward slice: the statements that feed the named method's statement(s) at a \
         line, walked interprocedurally up to `depth` call hops (default 2, max 500 nodes).",
        json!({
            "type": "object",
            "required": ["method", "line"],
            "properties": {
                "method": {"type": "string"},
                "line": {"type": "integer", "minimum": 1, "maximum": 4294967295_u64},
                "depth": {"type": "integer", "minimum": 0, "maximum": 32, "default": 2}
            }
        }),
    )
}

fn descriptor(name: &str, description: &str, input_schema: serde_json::Value) -> Tool {
    Tool {
        name: name.into(),
        description: description.into(),
        input_schema,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_exposes_the_cpg_tool_surface() {
        let registry = build_registry();
        for name in [
            "cpg.health",
            "cpg.parse",
            "cpg.callers_of",
            "cpg.callees_of",
            "cpg.definitions",
            "cpg.reaching_def",
            "cpg.taint_paths",
            "cpg.method_at",
            "cpg.cpg_size",
            "cpg.slice",
        ] {
            assert!(registry.contains(name), "missing {name}");
        }
        // Deliberately absent: no cpg-rs equivalent exists yet, and faking
        // them would be worse than routing to tree-sitter/clang.
        assert!(!registry.contains("cpg.unsafe_blocks"));
        assert!(!registry.contains("cpg.ffi_boundaries"));
    }

    #[test]
    fn joern_compatible_inputs_keep_their_field_names() {
        let registry = build_registry();
        let taint = registry
            .descriptors()
            .iter()
            .find(|tool| tool.name == "cpg.taint_paths")
            .unwrap();
        let required: Vec<&str> = taint.input_schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(required, vec!["source", "sink"]);
        assert!(taint.input_schema["properties"]["maxPaths"].is_object());
        assert!(taint.input_schema["properties"]["maxCallDepth"].is_object());
    }
}
