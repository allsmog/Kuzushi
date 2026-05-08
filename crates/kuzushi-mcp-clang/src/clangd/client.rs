use anyhow::{Context, Result};
use serde_json::Value;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

use super::protocol::{
    clangd_command, framed_lsp_message, initialize_params, notification_body, read_content_length,
    read_json_body, request_body, response_matches_id, response_result,
};

pub struct ClangdClient {
    pub(crate) child: Mutex<Child>,
    pub(crate) stdin: Mutex<ChildStdin>,
    pub(crate) stdout: Mutex<BufReader<ChildStdout>>,
    pub(crate) next_id: AtomicI64,
    pub(crate) initialized: Mutex<bool>,
}

impl ClangdClient {
    pub async fn spawn(repo: &std::path::Path) -> Result<Self> {
        let mut child = spawn_clangd(repo)?;
        let (stdin, stdout) = take_child_io(&mut child)?;
        Ok(Self::from_child_io(child, stdin, stdout))
    }

    pub(crate) fn from_child_io(child: Child, stdin: ChildStdin, stdout: ChildStdout) -> Self {
        Self {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            next_id: AtomicI64::new(1),
            initialized: Mutex::new(false),
        }
    }

    pub async fn initialize(&self, root: &std::path::Path) -> Result<()> {
        let mut init = self.initialized.lock().await;
        if *init {
            return Ok(());
        }
        self.send_initialize(root).await?;
        *init = true;
        Ok(())
    }

    pub(crate) async fn send_initialize(&self, root: &std::path::Path) -> Result<()> {
        let _ = self.request("initialize", initialize_params(root)).await?;
        self.notify("initialized", serde_json::json!({})).await
    }

    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.request("shutdown", Value::Null).await;
        let _ = self.notify("exit", Value::Null).await;
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
        Ok(())
    }

    pub async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let body = request_body(id, method, params);
        self.write_message(&body).await?;
        self.read_response_for_id(id).await
    }

    pub(crate) async fn read_response_for_id(&self, id: i64) -> Result<Value> {
        let resp = self.read_message().await?;
        if response_matches_id(&resp, id) {
            return response_result(resp);
        }
        Box::pin(self.read_response_for_id(id)).await
    }

    pub async fn notify(&self, method: &str, params: Value) -> Result<()> {
        let body = notification_body(method, params);
        self.write_message(&body).await
    }

    pub(crate) async fn write_message(&self, body: &Value) -> Result<()> {
        let message = framed_lsp_message(body)?;
        let mut stdin = self.stdin.lock().await;
        write_framed_message(&mut stdin, &message).await
    }

    pub(crate) async fn read_message(&self) -> Result<Value> {
        let mut stdout = self.stdout.lock().await;
        let len = read_content_length(&mut stdout).await?;
        read_json_body(&mut stdout, len).await
    }
}

pub(crate) fn spawn_clangd(repo: &std::path::Path) -> Result<Child> {
    clangd_command(repo)
        .spawn()
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
