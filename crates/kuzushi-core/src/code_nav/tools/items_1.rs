use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CodeNavTool {
    ReadSource,
    FindReferences,
    ListDefinitions,
    ReadDefinition,
}

impl CodeNavTool {
    pub fn name(self) -> &'static str {
        match self {
            Self::ReadSource => "read_source",
            Self::FindReferences => "find_references",
            Self::ListDefinitions => "list_definitions",
            Self::ReadDefinition => "read_definition",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CodeNavConfig {
    /// Workspace root. All path inputs resolve under here.
    pub root: PathBuf,
}

impl CodeNavConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

pub fn read_source_tool() -> AgentTool {
    AgentTool {
        name: "read_source".to_string(),
        description: "Read a slice of source code. Path is relative to the workspace root. \
                      Returns the file contents between start_line and end_line (1-indexed, \
                      inclusive). Reads larger than 64 KiB are truncated; use a narrower line \
                      range to avoid truncation."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "file": { "type": "string", "description": "Path relative to workspace root." },
                "start_line": { "type": "integer", "minimum": 1 },
                "end_line": { "type": "integer", "minimum": 1 }
            },
            "required": ["file"]
        }),
    }
}

pub fn find_references_tool() -> AgentTool {
    AgentTool {
        name: "find_references".to_string(),
        description: "Find references to a symbol via ripgrep. Returns up to 200 file:line:snippet \
                      hits. Use `scope` to narrow to a sub-tree and `language` to constrain by file \
                      type (e.g. \"c\", \"rust\", \"java\")."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "symbol":   { "type": "string", "description": "Symbol to search for (whole-word match)." },
                "scope":    { "type": "string", "description": "Optional sub-path under workspace root." },
                "language": { "type": "string", "description": "Optional rg --type filter (c, rust, java, …)." }
            },
            "required": ["symbol"]
        }),
    }
}

pub fn list_definitions_tool() -> AgentTool {
    AgentTool {
        name: "list_definitions".to_string(),
        description: "List function/struct/enum definitions in a file. Heuristic, may miss \
                      macro-heavy or templated definitions; verify with read_source if uncertain."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "file": { "type": "string", "description": "Path relative to workspace root." }
            },
            "required": ["file"]
        }),
    }
}
