use super::prelude::*;
use super::*;

pub fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
        .register(
            Tool {
                name: "gtags.health".into(),
                description: "Report whether `gtags` and `global` are available, with versions."
                    .into(),
                input_schema: json!({"type": "object", "properties": {}}),
            },
            HealthTool,
        )
        .register(
            Tool {
                name: "gtags.index".into(),
                description: "Build or refresh a gtags index for a repo path. Stores GTAGS/GRTAGS/GPATH inside the repo (gtags's default) or under `~/.kuzushi/index/gtags/<repo>/` when the repo is read-only."
                    .into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath"],
                    "properties": {
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            IndexTool,
        )
        .register(
            Tool {
                name: "gtags.definitions".into(),
                description: "Locate definitions of a symbol via `global -xd <symbol>`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["symbol"],
                    "properties": {
                        "symbol": {"type": "string"},
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            DefinitionsTool,
        )
        .register(
            Tool {
                name: "gtags.references".into(),
                description: "Locate references to a symbol via `global -xr <symbol>`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["symbol"],
                    "properties": {
                        "symbol": {"type": "string"},
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            ReferencesTool,
        )
        .register(
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
            },
            SymbolsInFileTool,
        )
        .register(
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
            },
            FilesMatchingTool,
        )
        .register(
            Tool {
                name: "gtags.completion".into(),
                description: "Return symbol-name completions for a prefix via `global -c <prefix>`."
                    .into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["prefix"],
                    "properties": {
                        "prefix": {"type": "string"},
                        "repoPath": {"type": "string"},
                    }
                }),
            },
            CompletionTool,
        )
}

pub(crate) struct HealthTool;

pub(crate) struct IndexTool;

pub(crate) struct DefinitionsTool;

pub(crate) struct ReferencesTool;

pub(crate) struct SymbolsInFileTool;

pub(crate) struct FilesMatchingTool;
