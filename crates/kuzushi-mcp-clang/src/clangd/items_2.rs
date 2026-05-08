use super::prelude::*;
use super::*;

pub(crate) fn clangd_command(repo: &std::path::Path) -> Command {
    let mut command = Command::new("clangd");
    command
        .arg("--background-index=false")
        .arg("--log=error")
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

pub(crate) fn take_child_stdin(child: &mut Child) -> Result<ChildStdin> {
    child.stdin.take().context("clangd stdin missing")
}

pub(crate) fn take_child_stdout(child: &mut Child) -> Result<ChildStdout> {
    child.stdout.take().context("clangd stdout missing")
}

pub(crate) fn initialize_params(root: &std::path::Path) -> Value {
    json!({
        "processId": std::process::id(),
        "rootUri": format!("file://{}", root.display()),
        "capabilities": {},
        "clientInfo": { "name": "kuzushi-mcp-clang", "version": env!("CARGO_PKG_VERSION") }
    })
}

pub(crate) fn request_body(id: i64, method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
}

pub(crate) fn notification_body(method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
}

pub(crate) fn framed_lsp_message(body: &Value) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(body)?;
    Ok(frame_raw_lsp_message(raw))
}

pub(crate) fn frame_raw_lsp_message(raw: Vec<u8>) -> Vec<u8> {
    let mut message = format!("Content-Length: {}\r\n\r\n", raw.len()).into_bytes();
    message.extend(raw);
    message
}

pub(crate) fn response_matches_id(response: &Value, id: i64) -> bool {
    response.get("id") == Some(&json!(id))
}

pub(crate) fn response_result(response: Value) -> Result<Value> {
    if let Some(err) = response.get("error") {
        anyhow::bail!("clangd error: {err}");
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

pub(crate) async fn read_content_length<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<usize> {
    let mut content_length: Option<usize> = None;
    let mut header_line = Vec::new();
    loop {
        match read_header_line(reader, &mut header_line).await? {
            HeaderLine::End => break,
            HeaderLine::Field(line) => record_content_length(&mut content_length, &line),
        }
    }
    content_length.context("clangd response missing Content-Length")
}

pub(crate) enum HeaderLine {
    End,
    Field(String),
}

pub(crate) async fn read_header_line<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    buf: &mut Vec<u8>,
) -> Result<HeaderLine> {
    buf.clear();
    let n = read_until_crlf(reader, buf).await?;
    if n == 0 {
        anyhow::bail!("clangd closed stdout");
    }
    header_line_from_bytes(buf)
}

pub(crate) fn header_line_from_bytes(buf: &[u8]) -> Result<HeaderLine> {
    let line = std::str::from_utf8(buf)?.trim_end_matches(['\r', '\n']);
    Ok(classify_header_line(line))
}

pub(crate) fn classify_header_line(line: &str) -> HeaderLine {
    if line.is_empty() {
        HeaderLine::End
    } else {
        HeaderLine::Field(line.to_string())
    }
}

pub(crate) fn record_content_length(content_length: &mut Option<usize>, line: &str) {
    if let Some(len) = content_length_value(line) {
        *content_length = Some(len);
    }
}
