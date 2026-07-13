use serde_json::{json, Value};

use crate::jsonrpc::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, ERROR_INVALID_PARAMS, ERROR_METHOD_NOT_FOUND,
    JSONRPC_VERSION,
};
use crate::tool::ToolRegistry;

use super::ServerInfo;

const MAX_INLINE_TOOL_TEXT_BYTES: usize = 64 * 1024;

pub(crate) async fn dispatch(
    req: &JsonRpcRequest,
    info: &ServerInfo,
    registry: &ToolRegistry,
) -> std::result::Result<Value, (i32, String)> {
    match req.method.as_str() {
        "initialize" => Ok(initialize_result(info)),
        "notifications/initialized" => Ok(Value::Null),
        "tools/list" => Ok(json!({ "tools": registry.descriptors() })),
        "tools/call" => call_tool(req, registry).await,
        "shutdown" | "exit" => Ok(Value::Null),
        other => Err((
            ERROR_METHOD_NOT_FOUND,
            format!("method not implemented: {other}"),
        )),
    }
}

fn initialize_result(info: &ServerInfo) -> Value {
    json!({
        "protocolVersion": info.protocol_version,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": info.name,
            "version": info.version,
        }
    })
}

async fn call_tool(
    req: &JsonRpcRequest,
    registry: &ToolRegistry,
) -> std::result::Result<Value, (i32, String)> {
    let params = req
        .params
        .as_ref()
        .ok_or((ERROR_INVALID_PARAMS, "missing params".to_string()))?;
    let name = tool_name(params)?;
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    if !registry.contains(name) {
        return Err((ERROR_METHOD_NOT_FOUND, format!("unknown tool: {name}")));
    }
    Ok(tool_call_result(registry, name, arguments).await)
}

fn tool_name(params: &Value) -> std::result::Result<&str, (i32, String)> {
    params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((ERROR_INVALID_PARAMS, "missing tool name".to_string()))
}

async fn tool_call_result(registry: &ToolRegistry, name: &str, arguments: Value) -> Value {
    match registry.call(name, arguments).await {
        Ok(value) => {
            let text = bounded_tool_text(&value);
            json!({
                "content": [{
                    "type": "text",
                    "text": text,
                }],
                "structuredContent": value,
                "isError": false,
            })
        }
        Err(err) => json!({
            "content": [{
                "type": "text",
                "text": err.to_string(),
            }],
            "isError": true,
        }),
    }
}

fn bounded_tool_text(value: &Value) -> String {
    match super::transport::bounded_json_bytes(value, MAX_INLINE_TOOL_TEXT_BYTES) {
        Ok(Some(bytes)) => String::from_utf8(bytes).unwrap_or_default(),
        Ok(None) => format!(
            "structured tool result omitted from text content because it exceeds {MAX_INLINE_TOOL_TEXT_BYTES} bytes"
        ),
        Err(error) => format!("structured tool result could not be rendered as text: {error}"),
    }
}

pub fn unbound_error(code: i32, message: impl Into<String>) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: Value::Null,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data: None,
        }),
    }
}
