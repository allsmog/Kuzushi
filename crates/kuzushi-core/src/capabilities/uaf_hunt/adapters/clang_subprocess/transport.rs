use anyhow::{Context, Result};
use serde_json::Value;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

mod pumps;

use crate::capabilities::uaf_hunt::adapters::local_limits::{
    MAX_MCP_FRAME_BYTES as MAX_FRAME_BYTES, MAX_MCP_RESPONSE_BYTES as MAX_RESPONSE_BYTES,
    MAX_MCP_SKIPPED_MESSAGES as MAX_SKIPPED_MESSAGES,
};

pub(super) struct RpcTransport {
    child: crate::scan::RegisteredChild,
    requests: Option<SyncSender<Vec<u8>>>,
    responses: Option<Receiver<Result<Vec<u8>>>>,
    workers: Vec<JoinHandle<()>>,
    cancellation: crate::scan::ScanCancellation,
    timeout: Duration,
    stopped: bool,
}

impl RpcTransport {
    pub(super) fn spawn(
        command: &mut Command,
        cancellation: Option<&crate::scan::ScanCancellation>,
        timeout: Duration,
    ) -> Result<Self> {
        anyhow::ensure!(
            !timeout.is_zero(),
            "uaf-hunt: MCP deadline must be positive"
        );
        let cancellation = cancellation.cloned().unwrap_or_default();
        ensure_active(&cancellation)?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let group = crate::scan::PreparedProcessGroup::configure(command)?;
        let mut child = command
            .spawn()
            .context("uaf-hunt: could not start mcp-clang")?;
        let pipes = take_pipes(&mut child);
        let child = cancellation.register_prepared_child(child, group)?;
        let (stdin, stdout) = pipes?;
        let (requests, input) = mpsc::sync_channel(1);
        let (events, responses) = mpsc::sync_channel(2);
        let reader = pumps::reader(stdout, events.clone());
        let writer = pumps::writer(stdin, input, events);
        Ok(Self {
            child,
            requests: Some(requests),
            responses: Some(responses),
            workers: vec![reader, writer],
            cancellation,
            timeout,
            stopped: false,
        })
    }

    pub(super) fn request(&mut self, request: &Value, id: u64) -> Result<Value> {
        anyhow::ensure!(
            !self.stopped,
            "uaf-hunt: MCP transport stopped after an earlier error"
        );
        let result = self.exchange(request, id);
        if result.is_err() {
            self.stop();
        }
        result
    }

    fn exchange(&self, request: &Value, id: u64) -> Result<Value> {
        ensure_active(&self.cancellation)?;
        let deadline = Instant::now() + self.timeout;
        let mut bytes = crate::checkpoint_limits::encode(request, MAX_FRAME_BYTES - 1)
            .context("uaf-hunt: MCP request byte limit exceeded")?;
        bytes.push(b'\n');
        self.requests
            .as_ref()
            .context("uaf-hunt: MCP writer closed")?
            .try_send(bytes)
            .context("uaf-hunt: MCP writer unavailable")?;
        self.read_matching(id, deadline)
    }

    fn read_matching(&self, id: u64, deadline: Instant) -> Result<Value> {
        let mut inspected = 0usize;
        for _ in 0..=MAX_SKIPPED_MESSAGES {
            let frame = self.next_frame(deadline)?;
            inspected = inspected.saturating_add(frame.len());
            anyhow::ensure!(
                inspected <= MAX_RESPONSE_BYTES,
                "uaf-hunt: MCP cumulative response byte limit exceeded"
            );
            if frame.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let response: Value =
                serde_json::from_slice(&frame).context("uaf-hunt: MCP response is not JSON")?;
            anyhow::ensure!(
                response["jsonrpc"] == "2.0",
                "uaf-hunt: invalid MCP response version"
            );
            if response["id"].as_u64() == Some(id) {
                return Ok(response);
            }
        }
        anyhow::bail!("uaf-hunt: MCP skipped-message limit exceeded")
    }

    fn next_frame(&self, deadline: Instant) -> Result<Vec<u8>> {
        let receiver = self
            .responses
            .as_ref()
            .context("uaf-hunt: MCP reader closed")?;
        loop {
            ensure_active(&self.cancellation)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            anyhow::ensure!(
                !remaining.is_zero(),
                "uaf-hunt: mcp-clang request timed out"
            );
            match receiver.recv_timeout(remaining.min(Duration::from_millis(25))) {
                Ok(result) => {
                    ensure_active(&self.cancellation)?;
                    return result;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("uaf-hunt: MCP reader stopped")
                }
            }
        }
    }

    fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        drop(self.requests.take());
        drop(self.responses.take());
        let _ = self.child.kill_and_wait();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }

    fn finish(&mut self) {
        if self.stopped {
            return;
        }
        if self.queue_shutdown() {
            self.wait_for_shutdown();
        }
        self.stop();
    }

    fn queue_shutdown(&self) -> bool {
        self.requests.as_ref().is_some_and(|sender| {
            sender
                .try_send(
                    b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"shutdown\",\"params\":null}\n"
                        .to_vec(),
                )
                .is_ok()
        })
    }

    fn wait_for_shutdown(&self) {
        let deadline = Instant::now() + Duration::from_millis(200);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for RpcTransport {
    fn drop(&mut self) {
        self.finish();
    }
}

fn ensure_active(cancellation: &crate::scan::ScanCancellation) -> Result<()> {
    anyhow::ensure!(
        !cancellation.is_cancelled(),
        "uaf-hunt: local work canceled"
    );
    Ok(())
}

fn take_pipes(child: &mut Child) -> Result<(ChildStdin, ChildStdout)> {
    let stdin = child.stdin.take().context("uaf-hunt: MCP stdin missing")?;
    let stdout = child
        .stdout
        .take()
        .context("uaf-hunt: MCP stdout missing")?;
    Ok((stdin, stdout))
}
