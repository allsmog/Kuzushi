use super::prelude::*;
use super::*;

pub(in crate::code_nav) fn handle_read_definition(
    root: &PathBuf,
    call: &ToolCall,
) -> Result<ToolResult> {
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

pub(in crate::code_nav) fn parse_or_err<T: serde::de::DeserializeOwned>(
    call: &ToolCall,
) -> Result<T> {
    serde_json::from_value(call.input.clone()).map_err(|e| {
        anyhow::anyhow!(
            "tool {:?}: input failed schema validation: {}",
            call.name,
            e
        )
    })
}
