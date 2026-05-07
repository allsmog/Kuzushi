use std::process::Stdio;
use std::sync::atomic::{AtomicI64, Ordering};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("MCP server exited unexpectedly")]
    Exited,
    #[error("MCP server returned error: {0}")]
    Server(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub struct McpClient {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    next_id: AtomicI64,
    initialized: Mutex<bool>,
    binary: String,
}

impl std::fmt::Debug for McpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpClient")
            .field("binary", &self.binary)
            .finish_non_exhaustive()
    }
}

impl McpClient {
    /// Spawn a server binary by name. Caller is responsible for ensuring
    /// the binary is on PATH; otherwise this errors.
    pub async fn spawn(binary: &str) -> Result<Self> {
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("could not spawn MCP server `{binary}`"))?;
        let stdin = child.stdin.take().context("server stdin missing")?;
        let stdout = child.stdout.take().context("server stdout missing")?;
        Ok(Self {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            next_id: AtomicI64::new(1),
            initialized: Mutex::new(false),
            binary: binary.to_string(),
        })
    }

    /// Send `initialize` if we haven't already.
    pub async fn ensure_initialized(&self) -> Result<()> {
        let mut init = self.initialized.lock().await;
        self.ensure_initialized_state(&mut init).await
    }

    async fn ensure_initialized_state(&self, init: &mut bool) -> Result<()> {
        if *init {
            return Ok(());
        }
        self.send_initialize().await?;
        *init = true;
        Ok(())
    }

    async fn send_initialize(&self) -> Result<()> {
        let _ = self.request("initialize", json!({})).await?;
        self.notify("notifications/initialized", json!({})).await
    }

    /// Call a tool by name. The MCP server returns a `content` array plus
    /// a `structuredContent` mirror; we prefer the latter when present.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        self.ensure_initialized().await?;
        let resp = self
            .request("tools/call", tool_call_params(name, arguments))
            .await?;
        tool_call_result(&self.binary, resp)
    }

    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.notify("shutdown", json!({})).await;
        let _ = self.notify("exit", json!({})).await;
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
        Ok(())
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.write_line(&json_rpc_request_body(id, method, params))
            .await?;
        self.read_response_for_id(id).await
    }

    async fn read_response_for_id(&self, id: i64) -> Result<Value> {
        loop {
            if let Some(result) = self.read_response_candidate(id).await? {
                return Ok(result);
            }
            // Notifications and responses to other ids are ignored; we
            // serialise calls so this should be rare in practice.
        }
    }

    async fn read_response_candidate(&self, id: i64) -> Result<Option<Value>> {
        let resp = self.read_line().await?;
        response_result_for_id(&self.binary, &resp, id)
    }

    async fn notify(&self, method: &str, params: Value) -> Result<()> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.write_line(&body).await
    }

    async fn write_line(&self, body: &Value) -> Result<()> {
        let raw = json_line(body)?;
        let mut stdin = self.stdin.lock().await;
        write_json_line(&mut stdin, &raw).await
    }

    async fn read_line(&self) -> Result<Value> {
        let line = self.read_raw_line().await?;
        parse_json_line(&line)
    }

    async fn read_raw_line(&self) -> Result<String> {
        let mut stdout = self.stdout.lock().await;
        let mut line = String::new();
        let n = stdout.read_line(&mut line).await?;
        ensure_server_line_read(n)?;
        Ok(line)
    }
}

fn ensure_server_line_read(bytes_read: usize) -> Result<()> {
    if bytes_read == 0 {
        return Err(anyhow::anyhow!(ClientError::Exited));
    }
    Ok(())
}

fn tool_call_params(name: &str, arguments: Value) -> Value {
    json!({ "name": name, "arguments": arguments })
}

fn json_rpc_request_body(id: i64, method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
}

fn tool_call_result(binary: &str, resp: Value) -> Result<Value> {
    if resp.get("isError") == Some(&json!(true)) {
        anyhow::bail!("{}: {}", binary, tool_error_message(&resp));
    }
    Ok(resp.get("structuredContent").cloned().unwrap_or(resp))
}

fn tool_error_message(resp: &Value) -> String {
    resp.get("content")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("(no error message)")
        .to_string()
}

fn response_result_for_id(binary: &str, resp: &Value, id: i64) -> Result<Option<Value>> {
    if resp.get("id") != Some(&json!(id)) {
        return Ok(None);
    }
    if let Some(err) = resp.get("error") {
        anyhow::bail!("{}: {err}", binary);
    }
    Ok(Some(resp.get("result").cloned().unwrap_or(Value::Null)))
}

fn parse_json_line(line: &str) -> Result<Value> {
    Ok(serde_json::from_str(line.trim_end())?)
}

fn json_line(body: &Value) -> Result<Vec<u8>> {
    let mut raw = serde_json::to_string(body)?;
    raw.push('\n');
    Ok(raw.into_bytes())
}

async fn write_json_line(stdin: &mut ChildStdin, raw: &[u8]) -> Result<()> {
    stdin.write_all(raw).await?;
    stdin.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawning a non-existent binary errors actionably.
    #[tokio::test]
    async fn spawn_missing_binary_errors() {
        let err = McpClient::spawn("kuzushi-no-such-mcp-binary-zzz")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("kuzushi-no-such-mcp-binary-zzz") || msg.contains("could not spawn"));
    }

    #[test]
    fn tool_call_result_prefers_structured_content_and_reports_errors() {
        assert_eq!(
            tool_call_params("clang.definition", json!({"file": "a.c"})),
            json!({"name": "clang.definition", "arguments": {"file": "a.c"}})
        );

        let structured = tool_call_result(
            "mcp",
            json!({
                "content": [{"text": "ignored"}],
                "structuredContent": {"ok": true}
            }),
        )
        .unwrap();
        assert_eq!(structured, json!({"ok": true}));

        let raw = tool_call_result("mcp", json!({"content": []})).unwrap();
        assert_eq!(raw, json!({"content": []}));

        let err = tool_call_result(
            "mcp",
            json!({"isError": true, "content": [{"text": "bad input"}]}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("mcp: bad input"));
    }

    #[test]
    fn response_matching_ignores_other_ids_and_extracts_errors_results_and_nulls() {
        assert_eq!(
            response_result_for_id("mcp", &json!({"id": 1, "result": {"ok": true}}), 2).unwrap(),
            None
        );
        assert_eq!(
            response_result_for_id("mcp", &json!({"id": 2, "result": {"ok": true}}), 2).unwrap(),
            Some(json!({"ok": true}))
        );
        assert_eq!(
            response_result_for_id("mcp", &json!({"id": 2}), 2).unwrap(),
            Some(Value::Null)
        );
        let err =
            response_result_for_id("mcp", &json!({"id": 2, "error": {"code": -1}}), 2).unwrap_err();
        assert!(err.to_string().contains("mcp"));
    }

    #[test]
    fn json_line_serializes_with_trailing_newline() {
        let raw = json_line(&json!({"jsonrpc": "2.0"})).unwrap();
        assert!(raw.ends_with(b"\n"));
        assert!(std::str::from_utf8(&raw).unwrap().contains("\"jsonrpc\""));
    }

    #[test]
    fn raw_line_helpers_parse_json_and_report_closed_server() {
        assert_eq!(
            parse_json_line("{\"ok\":true}\n").unwrap(),
            json!({"ok": true})
        );
        assert!(parse_json_line("{").is_err());
        assert!(ensure_server_line_read(1).is_ok());
        assert!(ensure_server_line_read(0)
            .unwrap_err()
            .to_string()
            .contains("exited"));
    }

    #[test]
    fn json_rpc_request_body_includes_id_method_and_params() {
        assert_eq!(
            json_rpc_request_body(7, "tools/list", json!({"cursor": null})),
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/list",
                "params": {"cursor": null}
            })
        );
    }
}
