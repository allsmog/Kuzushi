use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::runtime::{AgentTool, ToolBox, ToolCall, ToolResult};

use super::file_io::{read_source, ReadSourceInput};
use super::ripgrep::{find_references, FindReferencesInput};
use super::symbol_index::{
    list_definitions, read_definition, ListDefinitionsInput, ReadDefinitionInput,
};

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

pub fn read_definition_tool() -> AgentTool {
    AgentTool {
        name: "read_definition".to_string(),
        description: "Best-effort lookup of a symbol's definition: searches via find_references, \
                      picks the candidate that looks like a definition, and returns a 30-line \
                      window of source plus other candidate locations."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "name":      { "type": "string" },
                "hint_file": { "type": "string", "description": "Optional path to scope the search." }
            },
            "required": ["name"]
        }),
    }
}

pub fn code_nav_tool_specs() -> Vec<AgentTool> {
    vec![
        read_source_tool(),
        find_references_tool(),
        list_definitions_tool(),
        read_definition_tool(),
    ]
}

/// Build a [`ToolBox`] populated with handlers for the four code-nav
/// tools, all rooted at `cfg.root`. Failures from individual tool calls
/// are surfaced as `is_error: true` results, never panics.
pub fn code_nav_toolbox(cfg: CodeNavConfig) -> ToolBox {
    let mut tb = ToolBox::new();
    let root = Arc::new(cfg.root);

    {
        let root = Arc::clone(&root);
        tb.register("read_source", move |call| handle_read_source(&root, call));
    }
    {
        let root = Arc::clone(&root);
        tb.register("find_references", move |call| {
            handle_find_references(&root, call)
        });
    }
    {
        let root = Arc::clone(&root);
        tb.register("list_definitions", move |call| {
            handle_list_definitions(&root, call)
        });
    }
    {
        let root = Arc::clone(&root);
        tb.register("read_definition", move |call| {
            handle_read_definition(&root, call)
        });
    }
    tb
}

fn handle_read_source(root: &PathBuf, call: &ToolCall) -> Result<ToolResult> {
    let input: ReadSourceInput = parse_or_err(call)?;
    let result = match read_source(root, &input) {
        Ok(out) => ToolResult {
            call_id: call.call_id.clone(),
            output: serde_json::to_value(out)?,
            is_error: false,
        },
        Err(error) => ToolResult {
            call_id: call.call_id.clone(),
            output: json!({ "error": error.to_string() }),
            is_error: true,
        },
    };
    Ok(result)
}

fn handle_find_references(root: &PathBuf, call: &ToolCall) -> Result<ToolResult> {
    let input: FindReferencesInput = parse_or_err(call)?;
    let result = match find_references(root, &input) {
        Ok(out) => ToolResult {
            call_id: call.call_id.clone(),
            output: serde_json::to_value(out)?,
            is_error: false,
        },
        Err(error) => ToolResult {
            call_id: call.call_id.clone(),
            output: json!({ "error": error.to_string() }),
            is_error: true,
        },
    };
    Ok(result)
}

fn handle_list_definitions(root: &PathBuf, call: &ToolCall) -> Result<ToolResult> {
    let input: ListDefinitionsInput = parse_or_err(call)?;
    let result = match list_definitions(root, &input) {
        Ok(out) => ToolResult {
            call_id: call.call_id.clone(),
            output: serde_json::to_value(out)?,
            is_error: false,
        },
        Err(error) => ToolResult {
            call_id: call.call_id.clone(),
            output: json!({ "error": error.to_string() }),
            is_error: true,
        },
    };
    Ok(result)
}

fn handle_read_definition(root: &PathBuf, call: &ToolCall) -> Result<ToolResult> {
    let input: ReadDefinitionInput = parse_or_err(call)?;
    let result = match read_definition(root, &input) {
        Ok(out) => ToolResult {
            call_id: call.call_id.clone(),
            output: serde_json::to_value(out)?,
            is_error: false,
        },
        Err(error) => ToolResult {
            call_id: call.call_id.clone(),
            output: json!({ "error": error.to_string() }),
            is_error: true,
        },
    };
    Ok(result)
}

fn parse_or_err<T: serde::de::DeserializeOwned>(call: &ToolCall) -> Result<T> {
    serde_json::from_value(call.input.clone()).map_err(|e| {
        anyhow::anyhow!(
            "tool {:?}: input failed schema validation: {}",
            call.name,
            e
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn rg_available() -> bool {
        std::process::Command::new("rg")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn read_source_tool_round_trips_via_toolbox() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("a.rs"), "fn main() {}\n").unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));

        let call = ToolCall {
            name: "read_source".to_string(),
            input: json!({ "file": "a.rs" }),
            call_id: "c1".to_string(),
        };
        let result = crate::runtime::ToolCallHandler::run(&mut tb, &call).unwrap();
        assert!(!result.is_error, "{result:?}");
        let contents = result.output["contents"].as_str().unwrap();
        assert!(contents.contains("fn main"));
    }

    #[test]
    fn unknown_tool_in_box_returns_error_result() {
        let tmp = tempdir().unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));
        let call = ToolCall {
            name: "made_up_tool".to_string(),
            input: json!({}),
            call_id: "c1".to_string(),
        };
        let result = crate::runtime::ToolCallHandler::run(&mut tb, &call).unwrap();
        assert!(result.is_error);
    }

    #[test]
    fn find_references_tool_round_trips_via_toolbox() {
        if !rg_available() {
            eprintln!("rg not on PATH; skipping");
            return;
        }
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("a.rs"),
            "fn target() {}\nfn other() { target() }\n",
        )
        .unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));
        let call = ToolCall {
            name: "find_references".to_string(),
            input: json!({ "symbol": "target" }),
            call_id: "c1".to_string(),
        };
        let result = crate::runtime::ToolCallHandler::run(&mut tb, &call).unwrap();
        assert!(!result.is_error, "{result:?}");
        let hits = result.output["hits"].as_array().unwrap();
        assert!(hits.len() >= 2);
    }

    #[test]
    fn malformed_input_is_error_not_panic() {
        let tmp = tempdir().unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));
        let call = ToolCall {
            name: "read_source".to_string(),
            // Missing required `file`.
            input: json!({}),
            call_id: "c1".to_string(),
        };
        // The driver wraps anyhow errors as is_error results — but our
        // tool handler returns Err for schema failures so the driver path
        // would convert it. Here we verify the closure returns Err.
        let res = crate::runtime::ToolCallHandler::run(&mut tb, &call);
        assert!(res.is_err());
    }

    #[test]
    fn tool_specs_have_expected_names() {
        let specs = code_nav_tool_specs();
        let names: Vec<_> = specs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "read_source",
                "find_references",
                "list_definitions",
                "read_definition"
            ]
        );
    }

    #[test]
    fn code_nav_tool_names_match_registered_tool_names() {
        assert_eq!(CodeNavTool::ReadSource.name(), "read_source");
        assert_eq!(CodeNavTool::FindReferences.name(), "find_references");
        assert_eq!(CodeNavTool::ListDefinitions.name(), "list_definitions");
        assert_eq!(CodeNavTool::ReadDefinition.name(), "read_definition");
    }

    #[test]
    fn definition_tools_round_trip_via_toolbox() {
        if !rg_available() {
            eprintln!("rg not on PATH; skipping");
            return;
        }
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("lib.rs"),
            "pub struct User { id: u64 }\n\nfn load_user() -> User { User { id: 1 } }\n",
        )
        .unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));

        let list = crate::runtime::ToolCallHandler::run(
            &mut tb,
            &ToolCall {
                name: "list_definitions".to_string(),
                input: json!({ "file": "lib.rs" }),
                call_id: "list".to_string(),
            },
        )
        .unwrap();
        assert!(!list.is_error, "{list:?}");
        assert!(list.output["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["name"] == json!("load_user")));

        let read = crate::runtime::ToolCallHandler::run(
            &mut tb,
            &ToolCall {
                name: "read_definition".to_string(),
                input: json!({ "name": "load_user" }),
                call_id: "read".to_string(),
            },
        )
        .unwrap();
        assert!(!read.is_error, "{read:?}");
        assert!(read.output["source"]
            .as_str()
            .unwrap()
            .contains("fn load_user"));
    }
}
