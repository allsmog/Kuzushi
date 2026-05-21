use serde_json::Value;

pub(crate) fn unauthorized_response(tool_name: &str) -> Value {
    let message = format!("{tool_name} refuses to run: pass authorized=true to confirm you have authorization to test the target endpoint. This command can generate real traffic.");
    crate::module_result::failed_output_result(message.clone(), message, serde_json::json!({}))
}
