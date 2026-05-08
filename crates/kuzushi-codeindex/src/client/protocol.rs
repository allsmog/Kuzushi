use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::ChildStdin;

use super::ClientError;

pub(crate) fn ensure_server_line_read(bytes_read: usize) -> Result<()> {
    if bytes_read == 0 {
        return Err(anyhow::anyhow!(ClientError::Exited));
    }
    Ok(())
}

pub(crate) fn tool_call_params(name: &str, arguments: Value) -> Value {
    json!({ "name": name, "arguments": arguments })
}

pub(crate) fn json_rpc_request_body(id: i64, method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
}

pub(crate) fn tool_call_result(binary: &str, resp: Value) -> Result<Value> {
    if resp.get("isError") == Some(&json!(true)) {
        anyhow::bail!("{}: {}", binary, tool_error_message(&resp));
    }
    Ok(resp.get("structuredContent").cloned().unwrap_or(resp))
}

pub(crate) fn tool_error_message(resp: &Value) -> String {
    resp.get("content")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("(no error message)")
        .to_string()
}

pub(crate) fn response_result_for_id(binary: &str, resp: &Value, id: i64) -> Result<Option<Value>> {
    if resp.get("id") != Some(&json!(id)) {
        return Ok(None);
    }
    if let Some(err) = resp.get("error") {
        anyhow::bail!("{}: {err}", binary);
    }
    Ok(Some(resp.get("result").cloned().unwrap_or(Value::Null)))
}

pub(crate) fn parse_json_line(line: &str) -> Result<Value> {
    Ok(serde_json::from_str(line.trim_end())?)
}

pub(crate) fn json_line(body: &Value) -> Result<Vec<u8>> {
    let mut raw = serde_json::to_string(body)?;
    raw.push('\n');
    Ok(raw.into_bytes())
}

pub(crate) async fn write_json_line(stdin: &mut ChildStdin, raw: &[u8]) -> Result<()> {
    stdin.write_all(raw).await?;
    stdin.flush().await?;
    Ok(())
}
