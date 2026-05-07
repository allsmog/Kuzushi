use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::jsonrpc::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, ERROR_INVALID_PARAMS, ERROR_METHOD_NOT_FOUND,
    ERROR_PARSE, JSONRPC_VERSION,
};
use crate::tool::ToolRegistry;

/// Server identification reported in `initialize` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    /// MCP protocol version this server speaks (e.g. "2024-11-05").
    pub protocol_version: String,
}

impl ServerInfo {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            protocol_version: "2024-11-05".to_string(),
        }
    }
}

/// Run the MCP server loop on stdio until EOF. Blocks until stdin closes.
pub async fn serve_stdio(info: ServerInfo, registry: ToolRegistry) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    serve_streams(info, registry, stdin, stdout).await
}

/// Loop driver factored out for testing — accepts any `AsyncRead`/`AsyncWrite`.
pub async fn serve_streams<R, W>(
    info: ServerInfo,
    registry: ToolRegistry,
    reader: R,
    mut writer: W,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // EOF on stdin — clean shutdown.
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response = handle_message(trimmed, &info, &registry).await;
        if let Some(resp) = response {
            let encoded = serde_json::to_string(&resp)?;
            writer.write_all(encoded.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
    }
}

/// Process a single request line. Returns `None` for notifications (which
/// must not produce a response per JSON-RPC 2.0).
async fn handle_message(
    line: &str,
    info: &ServerInfo,
    registry: &ToolRegistry,
) -> Option<JsonRpcResponse> {
    let request: JsonRpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(err) => {
            // Parse error — respond with null id per JSON-RPC 2.0 spec.
            return Some(JsonRpcResponse::err(
                Value::Null,
                ERROR_PARSE,
                format!("parse error: {err}"),
            ));
        }
    };

    let id = request.id.clone();
    let result = dispatch(&request, info, registry).await;

    match (id, result) {
        // Notification: no id → no response, even on error.
        (None, _) => None,
        (Some(id), Ok(value)) => Some(JsonRpcResponse::ok(id, value)),
        (Some(id), Err((code, msg))) => Some(JsonRpcResponse::err(id, code, msg)),
    }
}

async fn dispatch(
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

/// Build a JSON-RPC error response with no id (e.g. for top-level fatal
/// errors that aren't tied to a specific request).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::{Tool, ToolHandler};
    use anyhow::Result;
    use async_trait::async_trait;
    use std::io::Cursor;

    struct EchoHandler;

    #[async_trait]
    impl ToolHandler for EchoHandler {
        async fn call(&self, args: Value) -> Result<Value> {
            Ok(json!({ "echoed": args }))
        }
    }

    fn make_registry() -> ToolRegistry {
        ToolRegistry::new().register(
            Tool {
                name: "echo".to_string(),
                description: "Echo args back.".to_string(),
                input_schema: json!({ "type": "object" }),
            },
            EchoHandler,
        )
    }

    async fn drive(input: &str) -> String {
        let info = ServerInfo::new("kuzushi-mcp-test", "0.0.0");
        let registry = make_registry();
        let reader = Cursor::new(input.as_bytes().to_vec());
        let mut output = Vec::new();
        serve_streams(info, registry, reader, &mut output)
            .await
            .unwrap();
        String::from_utf8(output).unwrap()
    }

    #[tokio::test]
    async fn initialize_returns_protocol_version() {
        let out = drive("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n").await;
        assert!(out.contains("\"protocolVersion\":\"2024-11-05\""));
        assert!(out.contains("\"name\":\"kuzushi-mcp-test\""));
    }

    #[tokio::test]
    async fn tools_list_returns_registered_tools() {
        let out = drive("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n").await;
        assert!(out.contains("\"name\":\"echo\""));
    }

    #[tokio::test]
    async fn tools_call_dispatches_and_wraps_response() {
        let out = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"k\":1}}}\n",
        )
        .await;
        assert!(out.contains("\"isError\":false"));
        assert!(out.contains("\"echoed\""));
        // Both a text content block and structuredContent should be present.
        assert!(out.contains("\"structuredContent\""));
    }

    #[tokio::test]
    async fn unknown_tool_returns_method_not_found() {
        let out = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"missing\"}}\n",
        )
        .await;
        assert!(out.contains("\"error\""));
        assert!(out.contains("-32601")); // method not found
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let out = drive("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"some/random\"}\n").await;
        assert!(out.contains("-32601"));
        assert!(out.contains("some/random"));
    }

    #[tokio::test]
    async fn parse_error_is_reported_with_null_id() {
        let out = drive("not json\n").await;
        assert!(out.contains("-32700")); // parse error
        assert!(out.contains("\"id\":null"));
    }

    #[tokio::test]
    async fn notification_produces_no_response() {
        let out = drive("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await;
        assert!(out.is_empty(), "notifications must not yield a response");
    }

    #[tokio::test]
    async fn empty_lines_are_skipped() {
        let out = drive("\n\n{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/list\"}\n\n").await;
        assert!(out.contains("\"name\":\"echo\""));
    }
}
