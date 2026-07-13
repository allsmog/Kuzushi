use super::*;
use kuzushi_mcp_common::tool::Tool;
use serde_json::json;

pub(super) fn register_file_tools(
    registry: ToolRegistry,
    handle: &Arc<ClangdHandle>,
) -> ToolRegistry {
    registry
        .register(
            file_tool(
                "clang.semantic_tokens",
                "Semantic tokens for an entire file via `textDocument/semanticTokens/full`.",
            ),
            SemanticTokensTool {
                handle: handle.clone(),
            },
        )
        .register(
            file_tool(
                "clang.diagnostics",
                "Pull-mode diagnostics for a file via LSP 3.17 `textDocument/diagnostic`.",
            ),
            DiagnosticsTool {
                handle: handle.clone(),
            },
        )
}

fn file_tool(name: &'static str, description: &'static str) -> Tool {
    Tool {
        name: name.into(),
        description: description.into(),
        input_schema: json!({
            "type": "object",
            "required": ["repoPath", "file"],
            "additionalProperties": false,
            "properties": {
                "repoPath": {"type": "string", "minLength": 1, "maxLength": 16384},
                "file": {"type": "string", "minLength": 1, "maxLength": 16384, "description": "Relative child path; absolute paths and parent traversal are rejected."}
            }
        }),
    }
}
