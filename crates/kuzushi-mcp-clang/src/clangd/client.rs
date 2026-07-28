use anyhow::{Context, Result};
use serde_json::Value;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{Mutex, MutexGuard};
use tokio::time::Instant;

use super::protocol::{
    clangd_command, framed_lsp_message, initialize_params, notification_body, read_content_length,
    read_json_body, request_body, response_matches_id, response_result,
};

const CLANGD_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SKIPPED_LSP_MESSAGES: usize = 64;
const MAX_CUMULATIVE_LSP_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SANITIZED_RESULT_BYTES: usize = 3 * 1024 * 1024;

pub struct ClangdClient {
    pub(crate) child: Mutex<Child>,
    pub(crate) stdin: Mutex<ChildStdin>,
    pub(crate) stdout: Mutex<BufReader<ChildStdout>>,
    pub(crate) next_id: AtomicI64,
    pub(crate) initialized: Mutex<bool>,
    pub(crate) request_gate: Mutex<()>,
    pub(crate) process_group_id: AtomicU32,
    pub(crate) _process_group: Option<kuzushi_mcp_common::process::ParentDeathProcessGroup>,
    pub(crate) _sandbox_scratch: Option<tempfile::TempDir>,
}

impl ClangdClient {
    pub async fn spawn(repo: kuzushi_mcp_common::AuthorizedDirectory) -> Result<Self> {
        let (mut child, scratch, process_group) = spawn_clangd(repo).await?;
        let (stdin, stdout) = take_child_io(&mut child)?;
        let mut client = Self::from_child_io(child, stdin, stdout);
        client._process_group = Some(process_group);
        client._sandbox_scratch = Some(scratch);
        Ok(client)
    }

    pub(crate) fn from_child_io(child: Child, stdin: ChildStdin, stdout: ChildStdout) -> Self {
        let process_group_id = child.id();
        Self {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            next_id: AtomicI64::new(1),
            initialized: Mutex::new(false),
            request_gate: Mutex::new(()),
            process_group_id: AtomicU32::new(process_group_id.unwrap_or(0)),
            _process_group: None,
            _sandbox_scratch: None,
        }
    }

    pub async fn initialize(&self, root: &std::path::Path) -> Result<()> {
        let deadline = Instant::now() + CLANGD_REQUEST_TIMEOUT;
        let mut init = match tokio::time::timeout_at(deadline, self.initialized.lock()).await {
            Ok(init) => init,
            Err(_) => {
                return self
                    .deadline_error("initialization", CLANGD_REQUEST_TIMEOUT)
                    .await
            }
        };
        if *init {
            return Ok(());
        }
        self.send_initialize_until(root, deadline).await?;
        *init = true;
        Ok(())
    }

    async fn send_initialize_until(&self, root: &std::path::Path, deadline: Instant) -> Result<()> {
        let _ = self
            .request_until(
                "initialize",
                initialize_params(root)?,
                deadline,
                CLANGD_REQUEST_TIMEOUT,
            )
            .await?;
        self.notify_until(
            "initialized",
            serde_json::json!({}),
            deadline,
            CLANGD_REQUEST_TIMEOUT,
        )
        .await
    }

    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.request("shutdown", Value::Null).await;
        let _ = self.notify("exit", Value::Null).await;
        self.kill_and_reap().await;
        Ok(())
    }

    pub async fn request(&self, method: &str, params: Value) -> Result<Value> {
        self.request_with_timeout(method, params, CLANGD_REQUEST_TIMEOUT)
            .await
    }

    pub(crate) async fn request_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value> {
        let deadline = Instant::now() + timeout;
        self.request_until(method, params, deadline, timeout).await
    }

    async fn request_until(
        &self,
        method: &str,
        params: Value,
        deadline: Instant,
        budget: Duration,
    ) -> Result<Value> {
        let _request = self.request_gate_until(deadline, "request", budget).await?;
        match tokio::time::timeout_at(deadline, self.request_inner(method, params)).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error)) => {
                self.kill_and_reap().await;
                Err(error.context("clangd protocol request failed; process was killed"))
            }
            Err(_) => self.deadline_error("request", budget).await,
        }
    }

    async fn request_inner(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let body = request_body(id, method, params);
        self.write_message(&body).await?;
        self.read_response_for_id(id).await
    }

    pub(crate) async fn read_response_for_id(&self, id: i64) -> Result<Value> {
        let mut cumulative_bytes = 0_usize;
        for _ in 0..MAX_SKIPPED_LSP_MESSAGES {
            let (response, response_bytes) = self.read_message().await?;
            cumulative_bytes = cumulative_bytes
                .checked_add(response_bytes)
                .context("clangd cumulative response size overflow")?;
            anyhow::ensure!(
                cumulative_bytes <= MAX_CUMULATIVE_LSP_RESPONSE_BYTES,
                "clangd responses exceed the {MAX_CUMULATIVE_LSP_RESPONSE_BYTES}-byte cumulative limit"
            );
            if response_matches_id(&response, id) {
                return bounded_sanitized_result(response_result(response)?);
            }
        }
        anyhow::bail!("clangd sent more than {MAX_SKIPPED_LSP_MESSAGES} unrelated messages")
    }

    pub async fn notify(&self, method: &str, params: Value) -> Result<()> {
        self.notify_with_timeout(method, params, CLANGD_REQUEST_TIMEOUT)
            .await
    }

    pub(crate) async fn notify_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        self.notify_until(method, params, deadline, timeout).await
    }

    async fn notify_until(
        &self,
        method: &str,
        params: Value,
        deadline: Instant,
        budget: Duration,
    ) -> Result<()> {
        let _request = self
            .request_gate_until(deadline, "notification", budget)
            .await?;
        match tokio::time::timeout_at(deadline, self.notify_inner(method, params)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.kill_and_reap().await;
                Err(error.context("clangd notification failed; process was killed"))
            }
            Err(_) => self.deadline_error("notification", budget).await,
        }
    }

    async fn request_gate_until(
        &self,
        deadline: Instant,
        operation: &str,
        budget: Duration,
    ) -> Result<MutexGuard<'_, ()>> {
        match tokio::time::timeout_at(deadline, self.request_gate.lock()).await {
            Ok(guard) => Ok(guard),
            Err(_) => self.deadline_error(operation, budget).await,
        }
    }

    async fn deadline_error<T>(&self, operation: &str, budget: Duration) -> Result<T> {
        self.kill_and_reap().await;
        anyhow::bail!(
            "clangd {operation} exceeded its {} ms deadline and was killed",
            budget.as_millis()
        )
    }

    async fn notify_inner(&self, method: &str, params: Value) -> Result<()> {
        let body = notification_body(method, params);
        self.write_message(&body).await
    }

    pub(crate) async fn write_message(&self, body: &Value) -> Result<()> {
        let message = framed_lsp_message(body)?;
        let mut stdin = self.stdin.lock().await;
        write_framed_message(&mut stdin, &message).await
    }

    pub(crate) async fn read_message(&self) -> Result<(Value, usize)> {
        let mut stdout = self.stdout.lock().await;
        let len = read_content_length(&mut stdout).await?;
        Ok((read_json_body(&mut stdout, len).await?, len))
    }

    pub(crate) async fn kill_and_reap(&self) {
        kill_process_group(self.process_group_id.load(Ordering::Acquire));
        let mut child = self.child.lock().await;
        let _ = child.start_kill();
        let _ = child.wait().await;
        self.process_group_id.store(0, Ordering::Release);
    }

    pub(crate) async fn is_running(&self) -> bool {
        let running = self
            .child
            .lock()
            .await
            .try_wait()
            .is_ok_and(|status| status.is_none());
        if !running {
            self.process_group_id.store(0, Ordering::Release);
        }
        running
    }
}

impl Drop for ClangdClient {
    fn drop(&mut self) {
        kill_process_group(self.process_group_id.swap(0, Ordering::AcqRel));
    }
}

fn bounded_sanitized_result(mut result: Value) -> Result<Value> {
    sanitize_json_strings(&mut result);
    let size = serde_json::to_vec(&result)?.len();
    anyhow::ensure!(
        size <= MAX_SANITIZED_RESULT_BYTES,
        "clangd result exceeds the {MAX_SANITIZED_RESULT_BYTES}-byte limit after terminal escaping"
    );
    Ok(result)
}

fn sanitize_json_strings(value: &mut Value) {
    match value {
        Value::String(text) => *text = kuzushi_mcp_common::process::sanitize_terminal_text(text),
        Value::Array(values) => values.iter_mut().for_each(sanitize_json_strings),
        Value::Object(values) => values.values_mut().for_each(sanitize_json_strings),
        _ => {}
    }
}

#[cfg(unix)]
fn kill_process_group(group_id: u32) {
    if group_id != 0 {
        // SAFETY: clangd was assigned this dedicated process group at spawn.
        unsafe {
            libc::killpg(group_id as libc::pid_t, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_process_group(_group_id: u32) {}

pub(crate) async fn spawn_clangd(
    repo: kuzushi_mcp_common::AuthorizedDirectory,
) -> Result<(
    Child,
    tempfile::TempDir,
    kuzushi_mcp_common::process::ParentDeathProcessGroup,
)> {
    clangd_command(repo)
        .await?
        .spawn("clangd")
        .context("could not spawn clangd")
}

pub(crate) fn take_child_io(child: &mut Child) -> Result<(ChildStdin, ChildStdout)> {
    let stdin = child.stdin.take().context("clangd stdin missing")?;
    let stdout = child.stdout.take().context("clangd stdout missing")?;
    Ok((stdin, stdout))
}

pub(crate) async fn write_framed_message(stdin: &mut ChildStdin, message: &[u8]) -> Result<()> {
    stdin.write_all(message).await?;
    stdin.flush().await?;
    Ok(())
}
