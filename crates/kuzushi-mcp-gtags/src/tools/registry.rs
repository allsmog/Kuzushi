use kuzushi_mcp_common::tool::{Tool, ToolRegistry};
use serde_json::json;

use super::tool_types::{
    CompletionTool, DefinitionsTool, FilesMatchingTool, HealthTool, IndexTool, ReferencesTool,
    SymbolsInFileTool,
};

pub fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
        .register(health_descriptor(), HealthTool)
        .register(index_descriptor(), IndexTool)
        .register(definitions_descriptor(), DefinitionsTool)
        .register(references_descriptor(), ReferencesTool)
        .register(symbols_in_file_descriptor(), SymbolsInFileTool)
        .register(files_matching_descriptor(), FilesMatchingTool)
        .register(completion_descriptor(), CompletionTool)
}

fn health_descriptor() -> Tool {
    Tool {
        name: "gtags.health".into(),
        description: "Report whether `gtags` and `global` are available, with versions.".into(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

fn index_descriptor() -> Tool {
    Tool {
        name: "gtags.index".into(),
        description: "Build or refresh a gtags index for a repo path.".into(),
        input_schema: json!({
            "type": "object",
            "required": ["repoPath"],
            "properties": {
                "repoPath": {"type": "string"},
            }
        }),
    }
}

fn definitions_descriptor() -> Tool {
    Tool {
        name: "gtags.definitions".into(),
        description: "Locate definitions of a symbol via `global -xd <symbol>`.".into(),
        input_schema: symbol_lookup_schema(),
    }
}

fn references_descriptor() -> Tool {
    Tool {
        name: "gtags.references".into(),
        description: "Locate references to a symbol via `global -xr <symbol>`.".into(),
        input_schema: symbol_lookup_schema(),
    }
}

fn symbol_lookup_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["symbol"],
        "properties": {
            "symbol": {"type": "string"},
            "repoPath": {"type": "string"},
        }
    })
}

fn symbols_in_file_descriptor() -> Tool {
    Tool {
        name: "gtags.symbols_in_file".into(),
        description: "List symbols defined in a file via `global -xf <file>`.".into(),
        input_schema: json!({
            "type": "object",
            "required": ["file"],
            "properties": {
                "file": {"type": "string"},
                "repoPath": {"type": "string"},
            }
        }),
    }
}

fn files_matching_descriptor() -> Tool {
    Tool {
        name: "gtags.files_matching".into(),
        description: "List indexed files matching a regex via `global -P <pattern>`.".into(),
        input_schema: json!({
            "type": "object",
            "required": ["pattern"],
            "properties": {
                "pattern": {"type": "string"},
                "repoPath": {"type": "string"},
            }
        }),
    }
}

fn completion_descriptor() -> Tool {
    Tool {
        name: "gtags.completion".into(),
        description: "Return symbol-name completions for a prefix via `global -c <prefix>`.".into(),
        input_schema: json!({
            "type": "object",
            "required": ["prefix"],
            "properties": {
                "prefix": {"type": "string"},
                "repoPath": {"type": "string"},
            }
        }),
    }
}
