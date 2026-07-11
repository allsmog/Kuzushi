use super::{
    dynamic_child_process_group_id, dynamic_host_command, validate_dynamic_host_handshake,
    DYNAMIC_EXECUTE_TIMEOUT,
};
use crate::runtime::{AgentQueryControl, AgentQueryRequest, AgentQueryResponse, AgentRuntime};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_STDERR_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_RUNTIME_PROTOCOL_LINE_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn run_dynamic_host_with_runtime(
    specifier: &str,
    name: &str,
    payload: Value,
    runtime: &dyn AgentRuntime,
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<Value> {
    let mut child = spawn_runtime_host(specifier, name)?;
    let mut stdin = take_runtime_stdin(&mut child)?;
    let stdout = take_runtime_stdout(&mut child)?;
    let stderr = take_runtime_stderr(&mut child)?;
    let stderr_drain = std::thread::spawn(move || drain_runtime_stderr(stderr));
    let process_group_id = dynamic_child_process_group_id(&child);
    let local_cancellation = crate::scan::ScanCancellation::default();
    let registered = local_cancellation.register_child(child, process_group_id)?;
    let deadline = Instant::now() + DYNAMIC_EXECUTE_TIMEOUT;
    let supervisor = RuntimeHostSupervisor::spawn(&local_cancellation, cancellation, deadline);
    if let Err(error) = write_initial_runtime_request(&mut stdin, payload) {
        drop(stdin);
        let _ = registered.kill_and_wait();
        supervisor.finish();
        let _ = stderr_drain.join();
        return Err(error);
    }

    let mut reader = BufReader::new(stdout);
    let control = AgentQueryControl::new(Some(local_cancellation.clone()), Some(deadline));
    let result = drive_dynamic_runtime_protocol(&mut reader, &mut stdin, runtime, name, &control);
    drop(stdin);
    let status = finish_runtime_host_after_protocol(&registered, &local_cancellation, &result);
    let supervision = supervisor.finish();
    let stderr = stderr_drain
        .join()
        .map_err(|_| anyhow::anyhow!("dynamic module stderr drain thread panicked"))??;
    ensure_runtime_supervision(supervision)?;
    if let Some(status) = status? {
        ensure_runtime_host_success(status, &stderr)?;
    }
    result
}

fn finish_runtime_host_after_protocol(
    child: &crate::scan::RegisteredChild,
    cancellation: &crate::scan::ScanCancellation,
    result: &Result<Value>,
) -> Result<Option<ExitStatus>> {
    if result.is_err() {
        child.kill_and_wait()?;
        return Ok(None);
    }
    wait_runtime_host(child, cancellation).map(Some)
}

struct RuntimeHostSupervisor {
    done: Arc<AtomicBool>,
    reason: Arc<AtomicU8>,
    thread: std::thread::JoinHandle<()>,
}

impl RuntimeHostSupervisor {
    fn spawn(
        local: &crate::scan::ScanCancellation,
        external: Option<&crate::scan::ScanCancellation>,
        deadline: Instant,
    ) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let reason = Arc::new(AtomicU8::new(0));
        let thread = spawn_runtime_watchdog(
            local.clone(),
            external.cloned(),
            Arc::clone(&done),
            Arc::clone(&reason),
            deadline,
        );
        Self {
            done,
            reason,
            thread,
        }
    }

    fn finish(self) -> u8 {
        self.done.store(true, Ordering::SeqCst);
        let _ = self.thread.join();
        self.reason.load(Ordering::SeqCst)
    }
}

fn spawn_runtime_watchdog(
    local: crate::scan::ScanCancellation,
    external: Option<crate::scan::ScanCancellation>,
    done: Arc<AtomicBool>,
    reason: Arc<AtomicU8>,
    deadline: Instant,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            if external
                .as_ref()
                .is_some_and(crate::scan::ScanCancellation::is_cancelled)
            {
                reason.store(1, Ordering::SeqCst);
                local.cancel();
                return;
            }
            if Instant::now() >= deadline {
                reason.store(2, Ordering::SeqCst);
                local.cancel();
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })
}

fn wait_runtime_host(
    child: &crate::scan::RegisteredChild,
    cancellation: &crate::scan::ScanCancellation,
) -> Result<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if cancellation.is_cancelled() {
            child.kill_and_wait()?;
            anyhow::bail!("dynamic module runtime host was killed")
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn ensure_runtime_supervision(reason: u8) -> Result<()> {
    match reason {
        1 => anyhow::bail!("dynamic module runtime host was cancelled and killed"),
        2 => anyhow::bail!(
            "dynamic module runtime host timed out after {}s and was killed",
            DYNAMIC_EXECUTE_TIMEOUT.as_secs()
        ),
        _ => Ok(()),
    }
}

fn spawn_runtime_host(specifier: &str, name: &str) -> Result<Child> {
    dynamic_host_command(["execute-runtime", specifier, name])?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not start node dynamic module host")
}

fn take_runtime_stdin(child: &mut Child) -> Result<ChildStdin> {
    child
        .stdin
        .take()
        .context("dynamic module host stdin was unavailable")
}

fn take_runtime_stdout(child: &mut Child) -> Result<ChildStdout> {
    child
        .stdout
        .take()
        .context("dynamic module host stdout was unavailable")
}

fn take_runtime_stderr(child: &mut Child) -> Result<ChildStderr> {
    child
        .stderr
        .take()
        .context("dynamic module host stderr was unavailable")
}

fn drain_runtime_stderr(mut stderr: ChildStderr) -> std::io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = stderr.read(&mut chunk)?;
        if read == 0 {
            return Ok(captured);
        }
        let remaining = MAX_STDERR_CAPTURE_BYTES.saturating_sub(captured.len());
        captured.extend_from_slice(&chunk[..read.min(remaining)]);
    }
}

fn write_initial_runtime_request(stdin: &mut impl Write, payload: Value) -> Result<()> {
    writeln!(
        stdin,
        "{}",
        serde_json::to_string(&json!({
            "type": "request",
            "payload": payload,
        }))?
    )
    .context("could not write dynamic module host request")
}

fn ensure_runtime_host_success(status: ExitStatus, stderr: &[u8]) -> Result<()> {
    if status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "dynamic module host failed: {}",
        String::from_utf8_lossy(stderr).trim()
    )
}

fn drive_dynamic_runtime_protocol(
    reader: &mut impl BufRead,
    stdin: &mut impl Write,
    runtime: &dyn AgentRuntime,
    tool_name: &str,
    control: &AgentQueryControl,
) -> Result<Value> {
    let mut line = Vec::new();
    read_runtime_host_handshake(reader, &mut line)?;
    loop {
        let read = read_bounded_protocol_line(reader, &mut line)?;
        if read == 0 {
            anyhow::bail!("dynamic tool {tool_name:?} exited before returning a result");
        }
        let message: Value = serde_json::from_slice(trim_protocol_line(&line))
            .context("dynamic module host emitted invalid protocol JSON")?;
        if let Some(value) = handle_dynamic_runtime_message(message, stdin, runtime, control)? {
            return Ok(value);
        }
    }
}

fn read_runtime_host_handshake(reader: &mut impl BufRead, line: &mut Vec<u8>) -> Result<()> {
    let read = read_bounded_protocol_line(reader, line)?;
    if read == 0 {
        anyhow::bail!("dynamic module host exited before its protocol handshake")
    }
    let message: Value = serde_json::from_slice(trim_protocol_line(line))
        .context("dynamic module host emitted an invalid protocol handshake")?;
    if message.get("type").and_then(Value::as_str) != Some("handshake") {
        anyhow::bail!("dynamic module host did not begin with a handshake")
    }
    validate_dynamic_host_handshake(&message)
}

fn read_bounded_protocol_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> Result<usize> {
    read_bounded_protocol_line_with_limit(reader, line, MAX_RUNTIME_PROTOCOL_LINE_BYTES)
}

fn read_bounded_protocol_line_with_limit(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    limit: usize,
) -> Result<usize> {
    line.clear();
    let read = reader
        .take((limit + 1) as u64)
        .read_until(b'\n', line)
        .context("could not read dynamic module host protocol line")?;
    if line.len() > limit {
        anyhow::bail!("dynamic module host protocol line exceeded {limit} bytes")
    }
    Ok(read)
}

fn trim_protocol_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn handle_dynamic_runtime_message(
    message: Value,
    stdin: &mut impl Write,
    runtime: &dyn AgentRuntime,
    control: &AgentQueryControl,
) -> Result<Option<Value>> {
    match message.get("type").and_then(Value::as_str) {
        Some("result") => message
            .get("value")
            .cloned()
            .map(Some)
            .context("dynamic module host result omitted value"),
        Some("runtime.query") => {
            handle_dynamic_runtime_query(&message, stdin, runtime, control)?;
            Ok(None)
        }
        Some(other) => anyhow::bail!("dynamic module host emitted unknown message {other:?}"),
        None => anyhow::bail!("dynamic module host protocol message omitted type"),
    }
}

fn handle_dynamic_runtime_query(
    message: &Value,
    stdin: &mut impl Write,
    runtime: &dyn AgentRuntime,
    control: &AgentQueryControl,
) -> Result<()> {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let request_value = message
        .get("request")
        .cloned()
        .context("runtime.query omitted request")?;
    let request: AgentQueryRequest =
        serde_json::from_value(request_value).context("runtime.query request is invalid")?;
    match runtime.query_blocking_controlled(request, control.clone()) {
        Ok(response) => write_dynamic_runtime_response(stdin, id, response),
        Err(error) => write_dynamic_runtime_error(stdin, id, &error.to_string()),
    }
}

fn write_dynamic_runtime_response(
    stdin: &mut impl Write,
    id: Value,
    response: AgentQueryResponse,
) -> Result<()> {
    writeln!(
        stdin,
        "{}",
        serde_json::to_string(&json!({
            "type": "runtime.response",
            "id": id,
            "response": response,
        }))?
    )
    .context("could not write dynamic runtime response")
}

fn write_dynamic_runtime_error(stdin: &mut impl Write, id: Value, error: &str) -> Result<()> {
    writeln!(
        stdin,
        "{}",
        serde_json::to_string(&json!({
            "type": "runtime.error",
            "id": id,
            "error": error,
        }))?
    )
    .context("could not write dynamic runtime error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::TriageOutcome;
    use crate::runtime::{AgentQueryResponse, TriageRequest};
    use std::io::Cursor;

    #[test]
    fn oversized_protocol_line_is_rejected_before_unbounded_growth() {
        let mut reader = Cursor::new(vec![b'x'; 18]);
        let mut line = Vec::new();

        let error = read_bounded_protocol_line_with_limit(&mut reader, &mut line, 16)
            .unwrap_err()
            .to_string();

        assert!(error.contains("exceeded 16 bytes"), "{error}");
        assert_eq!(line.len(), 17);
    }

    struct DeadlineLatchRuntime;

    #[async_trait::async_trait]
    impl AgentRuntime for DeadlineLatchRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            panic!("legacy callback must use the controlled runtime entrypoint")
        }

        fn query_blocking_controlled(
            &self,
            _request: AgentQueryRequest,
            control: AgentQueryControl,
        ) -> Result<AgentQueryResponse> {
            while !control.is_expired() {
                std::thread::sleep(Duration::from_millis(2));
            }
            control.ensure_active()?;
            unreachable!()
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("unused")
        }
    }

    #[test]
    fn runtime_callback_receives_invocation_deadline_control() {
        let message = json!({
            "type": "runtime.query",
            "id": 7,
            "request": {
                "model": "openai:gpt-5.5",
                "cwd": ".",
                "system_prompt": "system",
                "prompt": "prompt"
            }
        });
        let control =
            AgentQueryControl::new(None, Some(Instant::now() + Duration::from_millis(20)));
        let mut response = Vec::new();

        handle_dynamic_runtime_query(&message, &mut response, &DeadlineLatchRuntime, &control)
            .unwrap();

        let response = String::from_utf8(response).unwrap();
        assert!(response.contains("runtime.error"), "{response}");
        assert!(response.contains("deadline exceeded"), "{response}");
    }
}
