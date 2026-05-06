//! JSON-RPC client to a child MCP server.
//!
//! Spawns the named binary, connects to its stdin/stdout, sends `initialize`
//! once, and then routes `tools/call` requests one at a time. Each call
//! gets a fresh sequential id; responses are matched by id.
//!
//! This is deliberately small — for our purposes (local processes, no
//! concurrent calls per client) we don't need a request multiplexer.

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
        if *init {
            return Ok(());
        }
        let _ = self.request("initialize", json!({})).await?;
        self.notify("notifications/initialized", json!({})).await?;
        *init = true;
        Ok(())
    }

    /// Call a tool by name. The MCP server returns a `content` array plus
    /// a `structuredContent` mirror; we prefer the latter when present.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        self.ensure_initialized().await?;
        let resp = self
            .request(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            )
            .await?;

        if resp.get("isError") == Some(&json!(true)) {
            let msg = resp
                .get("content")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|item| item.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("(no error message)")
                .to_string();
            anyhow::bail!("{}: {}", self.binary, msg);
        }

        if let Some(structured) = resp.get("structuredContent") {
            return Ok(structured.clone());
        }
        Ok(resp)
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
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.write_line(&body).await?;
        loop {
            let resp = self.read_line().await?;
            if resp.get("id") == Some(&json!(id)) {
                if let Some(err) = resp.get("error") {
                    anyhow::bail!("{}: {err}", self.binary);
                }
                return Ok(resp.get("result").cloned().unwrap_or(Value::Null));
            }
            // Notifications and responses to other ids are ignored; we
            // serialise calls so this should be rare in practice.
        }
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
        let raw = serde_json::to_string(body)?;
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(raw.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok(())
    }

    async fn read_line(&self) -> Result<Value> {
        let mut stdout = self.stdout.lock().await;
        let mut line = String::new();
        let n = stdout.read_line(&mut line).await?;
        if n == 0 {
            return Err(anyhow::anyhow!(ClientError::Exited));
        }
        Ok(serde_json::from_str(line.trim_end())?)
    }
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
}
