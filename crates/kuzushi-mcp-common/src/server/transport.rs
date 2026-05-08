use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse, ERROR_PARSE};
use crate::tool::ToolRegistry;

use super::dispatch::dispatch;
use super::ServerInfo;

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
            return Ok(());
        }
        if let Some(resp) = handle_message(line.trim(), &info, &registry).await {
            write_jsonrpc_response(&mut writer, resp).await?;
        }
    }
}

pub(crate) async fn handle_message(
    line: &str,
    info: &ServerInfo,
    registry: &ToolRegistry,
) -> Option<JsonRpcResponse> {
    if line.is_empty() {
        return None;
    }
    let request = match parse_jsonrpc_request(line) {
        Ok(request) => request,
        Err(response) => return Some(response),
    };
    let id = request.id.clone();
    let result = dispatch(&request, info, registry).await;
    response_for_request_result(id, result)
}

fn parse_jsonrpc_request(line: &str) -> Result<JsonRpcRequest, JsonRpcResponse> {
    serde_json::from_str(line).map_err(|err| {
        JsonRpcResponse::err(Value::Null, ERROR_PARSE, format!("parse error: {err}"))
    })
}

fn response_for_request_result(
    id: Option<Value>,
    result: std::result::Result<Value, (i32, String)>,
) -> Option<JsonRpcResponse> {
    match (id, result) {
        (None, _) => None,
        (Some(id), Ok(value)) => Some(JsonRpcResponse::ok(id, value)),
        (Some(id), Err((code, msg))) => Some(JsonRpcResponse::err(id, code, msg)),
    }
}

async fn write_jsonrpc_response<W>(writer: &mut W, response: JsonRpcResponse) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let encoded = serde_json::to_string(&response)?;
    writer.write_all(encoded.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}
