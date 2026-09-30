use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use super::{
    ensure_server_line_read, json_line, json_rpc_request_body, parse_json_line,
    response_result_for_id, tool_call_params, tool_call_result, write_json_line, McpClient,
};

impl McpClient {
    /// Spawn a server binary by name. Caller is responsible for ensuring
    /// the binary is on PATH; otherwise this errors.
    pub async fn spawn(binary: &str) -> Result<Self> {
        let mut command = Command::new(binary);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut process_group =
            kuzushi_mcp_common::process::ParentDeathProcessGroup::configure(&mut command)
                .context("could not guard code-index MCP server process tree")?;
        let mut child = command
            .spawn()
            .with_context(|| format!("could not spawn MCP server `{binary}`"))?;
        process_group.attach_child(&child)?;
        let stdin = child.stdin.take().context("server stdin missing")?;
        let stdout = child.stdout.take().context("server stdout missing")?;
        let stderr = child.stderr.take().context("server stderr missing")?;
        Ok(Self {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            stderr_drain: Mutex::new(Some(spawn_stderr_drain(stderr))),
            next_id: AtomicI64::new(1),
            initialized: Mutex::new(false),
            request_gate: Mutex::new(()),
            retired: AtomicBool::new(false),
            binary: binary.to_string(),
            process_group,
        })
    }

    /// Send `initialize` if we haven't already.
    pub async fn ensure_initialized(&self) -> Result<()> {
        let mut init = self.initialized.lock().await;
        self.ensure_initialized_state(&mut init).await
    }

    pub(crate) async fn ensure_initialized_state(&self, init: &mut bool) -> Result<()> {
        if *init {
            return Ok(());
        }
        self.send_initialize().await?;
        *init = true;
        Ok(())
    }

    pub(crate) async fn send_initialize(&self) -> Result<()> {
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
        self.retire().await
    }

    pub(crate) async fn request(&self, method: &str, params: Value) -> Result<Value> {
        self.request_with_deadline(method, params, Duration::from_secs(30))
            .await
    }

    pub(crate) async fn request_with_deadline(
        &self,
        method: &str,
        params: Value,
        deadline: Duration,
    ) -> Result<Value> {
        match tokio::time::timeout(deadline, self.request_serialized(method, params)).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                self.retire()
                    .await
                    .context("retire failed code-index server")?;
                Err(error)
            }
            Err(_) => {
                self.retire()
                    .await
                    .context("retire timed-out code-index server")?;
                anyhow::bail!(
                    "{}: MCP {method} exceeded its {} ms deadline; client retired",
                    self.binary,
                    deadline.as_millis()
                )
            }
        }
    }

    async fn request_serialized(&self, method: &str, params: Value) -> Result<Value> {
        let _serial = self.request_gate.lock().await;
        anyhow::ensure!(
            !self.retired.load(Ordering::SeqCst),
            "MCP client is retired"
        );
        let mut guard = RequestGuard {
            client: self,
            complete: false,
        };
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.write_line(&json_rpc_request_body(id, method, params))
            .await?;
        let result = self.read_response_for_id(id).await;
        guard.complete = result.is_ok();
        result
    }

    pub(crate) async fn read_response_for_id(&self, id: i64) -> Result<Value> {
        for _ in 0..128 {
            if let Some(result) = self.read_response_candidate(id).await? {
                return Ok(result);
            }
        }
        anyhow::bail!("MCP server exceeded the 128-frame response search limit")
    }

    pub(crate) async fn read_response_candidate(&self, id: i64) -> Result<Option<Value>> {
        let resp = self.read_line().await?;
        response_result_for_id(&self.binary, &resp, id)
    }

    pub(crate) async fn notify(&self, method: &str, params: Value) -> Result<()> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let result = tokio::time::timeout(Duration::from_secs(1), self.write_line(&body))
            .await
            .context("MCP notification write timed out")
            .and_then(|result| result);
        if result.is_err() {
            self.retire().await?;
        }
        result
    }

    pub(crate) async fn write_line(&self, body: &Value) -> Result<()> {
        let raw = json_line(body)?;
        let mut stdin = self.stdin.lock().await;
        write_json_line(&mut stdin, &raw).await
    }

    pub(crate) async fn read_line(&self) -> Result<Value> {
        let line = self.read_raw_line().await?;
        parse_json_line(&line)
    }

    pub(crate) async fn read_raw_line(&self) -> Result<String> {
        let mut stdout = self.stdout.lock().await;
        let mut line = String::new();
        let n = (&mut *stdout)
            .take(MAX_RESPONSE_FRAME_BYTES as u64 + 1)
            .read_line(&mut line)
            .await?;
        anyhow::ensure!(
            n <= MAX_RESPONSE_FRAME_BYTES,
            "MCP response frame exceeds 4 MiB"
        );
        ensure_server_line_read(n)?;
        Ok(line)
    }

    async fn retire(&self) -> Result<()> {
        self.retired.store(true, Ordering::SeqCst);
        self.process_group.kill();
        let mut child = self.child.lock().await;
        child.start_kill()?;
        tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .context("MCP child did not exit after termination")??;
        drop(child);
        let drain = self.stderr_drain.lock().await.take();
        if let Some(drain) = drain {
            drain.abort();
        }
        Ok(())
    }
}

const MAX_RESPONSE_FRAME_BYTES: usize = 4 * 1024 * 1024;
const STDERR_DRAIN_BUFFER_BYTES: usize = 8 * 1024;

#[cfg(all(test, unix))]
#[path = "supervision_tests.rs"]
mod supervision_tests;

struct RequestGuard<'a> {
    client: &'a McpClient,
    complete: bool,
}

impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.client.retired.store(true, Ordering::SeqCst);
            self.client.process_group.kill();
        }
    }
}

pub(crate) fn spawn_stderr_drain<R>(mut stderr: R) -> JoinHandle<u64>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = [0_u8; STDERR_DRAIN_BUFFER_BYTES];
        let mut drained_bytes = 0_u64;
        while let Ok(read) = stderr.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            drained_bytes = drained_bytes.saturating_add(read as u64);
        }
        drained_bytes
    })
}
