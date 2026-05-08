use super::prelude::*;
use super::*;

pub(crate) async fn dispatch(
    req: &JsonRpcRequest,
    info: &ServerInfo,
    registry: &ToolRegistry,
) -> std::result::Result<Value, (i32, String)> {
    match req.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": info.protocol_version,
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": info.name,
                "version": info.version,
            }
        })),

        "notifications/initialized" => Ok(Value::Null),

        "tools/list" => Ok(json!({ "tools": registry.descriptors() })),

        "tools/call" => {
            let params = req
                .params
                .as_ref()
                .ok_or((ERROR_INVALID_PARAMS, "missing params".to_string()))?;
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or((ERROR_INVALID_PARAMS, "missing tool name".to_string()))?;
            let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

            if !registry.contains(name) {
                return Err((ERROR_METHOD_NOT_FOUND, format!("unknown tool: {name}")));
            }

            match registry.call(name, arguments).await {
                Ok(value) => Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&value).unwrap_or_default(),
                    }],
                    "structuredContent": value,
                    "isError": false,
                })),
                Err(err) => Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": err.to_string(),
                    }],
                    "isError": true,
                })),
            }
        }

        "shutdown" => Ok(Value::Null),
        "exit" => Ok(Value::Null),

        other => Err((
            ERROR_METHOD_NOT_FOUND,
            format!("method not implemented: {other}"),
        )),
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
