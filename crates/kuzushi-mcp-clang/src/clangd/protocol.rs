use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

pub(crate) const MAX_LSP_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_LSP_HEADER_BYTES: usize = 8 * 1024;
const MAX_LSP_HEADER_FIELDS: usize = 64;

pub(crate) fn initialize_params(root: &std::path::Path) -> Result<Value> {
    Ok(json!({
        "processId": std::process::id(),
        "rootUri": file_uri(root)?,
        "capabilities": {},
        "clientInfo": { "name": "kuzushi-mcp-clang", "version": env!("CARGO_PKG_VERSION") }
    }))
}

pub(crate) fn file_uri(path: &std::path::Path) -> Result<String> {
    url::Url::from_file_path(path)
        .map(String::from)
        .map_err(|_| anyhow::anyhow!("could not encode absolute file URI for {}", path.display()))
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
    anyhow::ensure!(
        raw.len() <= MAX_LSP_BODY_BYTES,
        "clangd request exceeds the {MAX_LSP_BODY_BYTES}-byte limit"
    );
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
        let error = kuzushi_mcp_common::process::sanitize_terminal_text(&err.to_string());
        anyhow::bail!("clangd error: {error}");
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

pub(crate) async fn read_content_length<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<usize> {
    let mut content_length: Option<usize> = None;
    let mut header_line = Vec::new();
    for _ in 0..MAX_LSP_HEADER_FIELDS {
        match read_header_line(reader, &mut header_line).await? {
            HeaderLine::End => {
                let length = content_length.context("clangd response missing Content-Length")?;
                anyhow::ensure!(
                    length <= MAX_LSP_BODY_BYTES,
                    "clangd response exceeds the {MAX_LSP_BODY_BYTES}-byte limit"
                );
                return Ok(length);
            }
            HeaderLine::Field(line) => record_content_length(&mut content_length, &line)?,
        }
    }
    anyhow::bail!("clangd response has more than {MAX_LSP_HEADER_FIELDS} header fields")
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

pub(crate) fn record_content_length(content_length: &mut Option<usize>, line: &str) -> Result<()> {
    if let Some(len) = content_length_value(line) {
        anyhow::ensure!(
            content_length.is_none(),
            "clangd response has duplicate Content-Length headers"
        );
        *content_length = Some(len);
    }
    Ok(())
}

pub(crate) fn content_length_value(line: &str) -> Option<usize> {
    let rest = line
        .strip_prefix("Content-Length:")
        .or_else(|| line.strip_prefix("content-length:"))?;
    rest.trim().parse().ok()
}

pub(crate) async fn read_json_body<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    len: usize,
) -> Result<Value> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

pub(crate) async fn read_until_crlf<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    buf: &mut Vec<u8>,
) -> Result<usize> {
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(buf.len());
        }
        buf.push(byte[0]);
        anyhow::ensure!(
            buf.len() <= MAX_LSP_HEADER_BYTES,
            "clangd header exceeds the {MAX_LSP_HEADER_BYTES}-byte limit"
        );
        if buf.ends_with(b"\r\n") {
            return Ok(buf.len());
        }
    }
}
