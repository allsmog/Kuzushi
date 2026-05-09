use serde_json::{json, Value};

pub(crate) fn unauthorized_response(tool_name: &str) -> Value {
    json!({
        "ok": false,
        "output": format!("{tool_name} refuses to run: pass authorized=true to confirm you have authorization to test the target endpoint. This command can generate real traffic."),
    })
}
