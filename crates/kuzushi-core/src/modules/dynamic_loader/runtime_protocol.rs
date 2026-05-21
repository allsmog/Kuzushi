use super::dynamic_host_command;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Output, Stdio};

pub(super) fn run_dynamic_host_with_runtime(
    specifier: &str,
    name: &str,
    payload: Value,
    runtime: &dyn AgentRuntime,
) -> Result<Value> {
    let mut child = spawn_runtime_host(specifier, name)?;
    let mut stdin = take_runtime_stdin(&mut child)?;
    let stdout = take_runtime_stdout(&mut child)?;
    write_initial_runtime_request(&mut stdin, payload)?;

    let mut reader = BufReader::new(stdout);
    let result = drive_dynamic_runtime_protocol(&mut reader, &mut stdin, runtime, name);
    drop(stdin);
    ensure_runtime_host_success(
        child
            .wait_with_output()
            .context("could not read dynamic module host output")?,
    )?;
    result
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

fn ensure_runtime_host_success(output: Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "dynamic module host failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn drive_dynamic_runtime_protocol(
    reader: &mut impl BufRead,
    stdin: &mut impl Write,
    runtime: &dyn AgentRuntime,
    tool_name: &str,
) -> Result<Value> {
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .context("could not read dynamic module host protocol line")?;
        if read == 0 {
            anyhow::bail!("dynamic tool {tool_name:?} exited before returning a result");
        }
        let message: Value = serde_json::from_str(line.trim_end())
            .context("dynamic module host emitted invalid protocol JSON")?;
        if let Some(value) = handle_dynamic_runtime_message(message, stdin, runtime)? {
            return Ok(value);
        }
    }
}

fn handle_dynamic_runtime_message(
    message: Value,
    stdin: &mut impl Write,
    runtime: &dyn AgentRuntime,
) -> Result<Option<Value>> {
    match message.get("type").and_then(Value::as_str) {
        Some("result") => message
            .get("value")
            .cloned()
            .map(Some)
            .context("dynamic module host result omitted value"),
        Some("runtime.query") => {
            handle_dynamic_runtime_query(&message, stdin, runtime)?;
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
) -> Result<()> {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let request_value = message
        .get("request")
        .cloned()
        .context("runtime.query omitted request")?;
    let request: AgentQueryRequest =
        serde_json::from_value(request_value).context("runtime.query request is invalid")?;
    match runtime.query_blocking(request) {
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
