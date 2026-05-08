use super::*;

pub fn build_registry() -> ToolRegistry {
    let handle = Arc::new(ClangdHandle::default());

    ToolRegistry::new()
        .register(
            Tool {
                name: "clang.health".into(),
                description: "Report whether clangd and clang are available, with versions.".into(),
                input_schema: json!({"type": "object", "properties": {}}),
            },
            HealthTool,
        )
        .register(
            Tool {
                name: "clang.compile_commands".into(),
                description: "Locate or generate compile_commands.json for a repo.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath"],
                    "properties": { "repoPath": {"type": "string"} }
                }),
            },
            CompileCommandsTool,
        )
        .register(
            Tool {
                name: "clang.definition".into(),
                description: "Forward to clangd `textDocument/definition` and return canonical Locations.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            DefinitionTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.references".into(),
                description: "Forward to clangd `textDocument/references` and return canonical Locations.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            ReferencesTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.type_at".into(),
                description: "Forward to clangd `textDocument/hover` and return type information at a position.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            TypeAtTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.ast".into(),
                description: "Forward to clangd `textDocument/ast` (clangd extension) and return the AST subtree at a position.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            AstTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.callers".into(),
                description: "Incoming call-hierarchy: methods that call the symbol at (file, line, column). Wraps clangd `callHierarchy/incomingCalls`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            CallersTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.callees".into(),
                description: "Outgoing call-hierarchy: methods called by the symbol at (file, line, column). Wraps clangd `callHierarchy/outgoingCalls`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            CalleesTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.macro_expand".into(),
                description: "Macro expansion at a position via clangd hover (clangd renders the expansion in markdown).".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            MacroExpandTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.semantic_tokens".into(),
                description: "Semantic tokens for an entire file via `textDocument/semanticTokens/full`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"}
                    }
                }),
            },
            SemanticTokensTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.diagnostics".into(),
                description: "Pull-mode diagnostics for a file via LSP 3.17 `textDocument/diagnostic`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"}
                    }
                }),
            },
            DiagnosticsTool {
                handle: handle.clone(),
            },
        )
}
