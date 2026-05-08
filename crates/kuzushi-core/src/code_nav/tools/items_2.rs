use super::prelude::*;
use super::*;

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

pub(in crate::code_nav) fn handle_read_source(
    root: &PathBuf,
    call: &ToolCall,
) -> Result<ToolResult> {
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

pub(in crate::code_nav) fn handle_find_references(
    root: &PathBuf,
    call: &ToolCall,
) -> Result<ToolResult> {
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

pub(in crate::code_nav) fn handle_list_definitions(
    root: &PathBuf,
    call: &ToolCall,
) -> Result<ToolResult> {
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
