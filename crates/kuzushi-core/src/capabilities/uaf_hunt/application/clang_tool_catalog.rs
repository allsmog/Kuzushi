use crate::runtime::AgentTool;
use serde_json::json;

/// JSON Schema fragment shared by every position-anchored clangd tool.
fn position_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["file", "line", "column"],
        "properties": {
            "file": {
                "type": "string",
                "description": "Repository-relative path to a C/C++ source or header file.",
            },
            "line": {
                "type": "integer",
                "minimum": 1,
                "description": "1-indexed line number where the symbol appears.",
            },
            "column": {
                "type": "integer",
                "minimum": 1,
                "description": "1-indexed column on `line` pointing at the symbol's name.",
            },
        },
        "additionalProperties": false,
    })
}

/// Schemas for read-only repo-walking tools that complement the clang
/// tools. The agent uses these for the structural pass (find call
/// sites of `malloc`, list candidate functions) before drilling in
/// with `clang.callers` / `clang.callees`.
fn read_file_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["file"],
        "properties": {
            "file": {"type": "string", "description": "Repo-relative file path."},
            "startLine": {"type": "integer", "minimum": 1},
            "endLine": {"type": "integer", "minimum": 1},
        },
        "additionalProperties": false,
    })
}

fn grep_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["pattern"],
        "properties": {
            "pattern": {
                "type": "string",
                "description": "Literal substring or basic regex to search for.",
            },
            "globs": {
                "type": "array",
                "items": {"type": "string"},
                "description": "File globs to restrict the search. Defaults to production C/C++ sources and excludes tests/docs/examples/fixtures unless includeNonProduction is true.",
            },
            "maxResults": {"type": "integer", "minimum": 1, "maximum": 200},
        },
        "additionalProperties": false,
    })
}

fn list_dir_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Repo-relative directory (default: `.`)."},
        },
        "additionalProperties": false,
    })
}

/// Returns the complete `AgentTool` catalog for the uaf-hunt agent.
/// The five `clang.*` tools wrap the mcp-clang subprocess; the three
/// repo tools (`grep`, `read_file`, `list_dir`) are handled directly
/// inside the toolbox.
pub fn uaf_hunt_agent_tools() -> Vec<AgentTool> {
    vec![
        AgentTool {
            name: "clang_callers".to_string(),
            description: "Incoming call hierarchy: which functions call the symbol at \
                          (file, line, column). Wraps clangd `callHierarchy/incomingCalls`. \
                          Use this to walk from a free site upward toward its callers, then \
                          look for reachable post-free uses of the freed pointer."
                .to_string(),
            input_schema: position_schema(),
        },
        AgentTool {
            name: "clang_callees".to_string(),
            description: "Outgoing call hierarchy: functions called by the symbol at \
                          (file, line, column). Wraps clangd `callHierarchy/outgoingCalls`. \
                          Use this to ask whether a function eventually calls free/zfree/\
                          sdsfree/etc. on a pointer it received."
                .to_string(),
            input_schema: position_schema(),
        },
        AgentTool {
            name: "clang_references".to_string(),
            description: "All reference sites of the symbol at (file, line, column). \
                          Use this to enumerate every use of a pointer variable so you \
                          can check ordering against the free site."
                .to_string(),
            input_schema: position_schema(),
        },
        AgentTool {
            name: "clang_definition".to_string(),
            description: "Definition location for the symbol at (file, line, column). \
                          Use this to jump from a call site to the function body."
                .to_string(),
            input_schema: position_schema(),
        },
        AgentTool {
            name: "clang_type_at".to_string(),
            description: "Type information at (file, line, column) via clangd hover. \
                          Use this to confirm the type of a freed pointer before claiming \
                          a use-after-free."
                .to_string(),
            input_schema: position_schema(),
        },
        AgentTool {
            name: "grep".to_string(),
            description: "Literal/basic-regex search restricted to C/C++ source files by default. \
                          Returns matches as `path:line:text`. Use this to find call sites of an \
                          alloc or free function, then promote to clang_* tools for call-graph \
                          analysis."
                .to_string(),
            input_schema: grep_schema(),
        },
        AgentTool {
            name: "read_file".to_string(),
            description: "Read repo-relative source file or a line range from it. Use this to \
                          inspect a candidate function body before submitting a finding."
                .to_string(),
            input_schema: read_file_schema(),
        },
        AgentTool {
            name: "list_dir".to_string(),
            description: "List the contents of a repo-relative directory.".to_string(),
            input_schema: list_dir_schema(),
        },
    ]
}
