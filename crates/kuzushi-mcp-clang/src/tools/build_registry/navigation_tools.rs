use super::*;
use kuzushi_mcp_common::tool::Tool;
use serde_json::{json, Value};

pub(super) fn register_navigation_tools(
    registry: ToolRegistry,
    handle: &Arc<ClangdHandle>,
) -> ToolRegistry {
    registry
        .register(position_tool("clang.definition", "Forward to clangd `textDocument/definition` and return canonical Locations."), DefinitionTool { handle: handle.clone() })
        .register(position_tool("clang.references", "Forward to clangd `textDocument/references` and return canonical Locations."), ReferencesTool { handle: handle.clone() })
        .register(position_tool("clang.type_at", "Forward to clangd `textDocument/hover` and return type information at a position."), TypeAtTool { handle: handle.clone() })
        .register(ast_tool(), AstTool { handle: handle.clone() })
        .register(position_tool("clang.callers", "Incoming call-hierarchy: methods that call the symbol at (file, line, column). Wraps clangd `callHierarchy/incomingCalls`."), CallersTool { handle: handle.clone() })
        .register(position_tool("clang.callees", "Outgoing call-hierarchy: methods called by the symbol at (file, line, column). Wraps clangd `callHierarchy/outgoingCalls`."), CalleesTool { handle: handle.clone() })
        .register(position_tool("clang.macro_expand", "Macro expansion at a position via clangd hover (clangd renders the expansion in markdown)."), MacroExpandTool { handle: handle.clone() })
}

fn position_tool(name: &'static str, description: &'static str) -> Tool {
    Tool {
        name: name.into(),
        description: description.into(),
        input_schema: position_schema(&["repoPath", "file", "line", "column"]),
    }
}

fn ast_tool() -> Tool {
    Tool {
        name: "clang.ast".into(),
        description: "Forward to clangd `textDocument/ast` (clangd extension) and return the AST subtree at a position.".into(),
        input_schema: position_schema(&["repoPath", "file", "line"]),
    }
}

fn position_schema(required: &[&str]) -> Value {
    json!({
        "type": "object",
        "required": required,
        "additionalProperties": false,
        "properties": {
            "repoPath": {"type": "string", "minLength": 1, "maxLength": 16384},
            "file": {"type": "string", "minLength": 1, "maxLength": 16384, "description": "Relative child path; absolute paths and parent traversal are rejected."},
            "line": {"type": "integer", "minimum": 1},
            "column": {"type": "integer", "minimum": 1}
        }
    })
}
