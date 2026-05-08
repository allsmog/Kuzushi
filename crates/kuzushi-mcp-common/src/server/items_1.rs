use super::prelude::*;
use super::*;

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

pub async fn serve_stdio(info: ServerInfo, registry: ToolRegistry) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    serve_streams(info, registry, stdin, stdout).await
}

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

pub(crate) async fn handle_message(
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
