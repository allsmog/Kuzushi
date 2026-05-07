//! Minimal clangd LSP client.
//!
//! Spawns clangd as a child process and speaks LSP (JSON-RPC framed by
//! `Content-Length` headers) over its stdin/stdout. Only the few methods
//! we actually call are implemented:
//! - `initialize`
//! - `textDocument/definition`
//! - `textDocument/references`
//! - `textDocument/ast` (clangd-specific extension)
//! - `textDocument/hover` (used to derive type info for `clang.type_at`)
//!
//! This is deliberately thin — it's not a general-purpose LSP client.
//! Each request gets a fresh sequential id; responses are matched by id.

use std::process::Stdio;
use std::sync::atomic::{AtomicI64, Ordering};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

pub struct ClangdClient {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    next_id: AtomicI64,
    initialized: Mutex<bool>,
}

impl ClangdClient {
    pub async fn spawn(repo: &std::path::Path) -> Result<Self> {
        let mut child = clangd_command(repo)
            .spawn()
            .context("could not spawn clangd")?;
        let stdin = take_child_stdin(&mut child)?;
        let stdout = take_child_stdout(&mut child)?;
        Ok(Self::from_child_io(child, stdin, stdout))
    }

    fn from_child_io(child: Child, stdin: ChildStdin, stdout: ChildStdout) -> Self {
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

    async fn send_initialize(&self, root: &std::path::Path) -> Result<()> {
        let _ = self.request("initialize", initialize_params(root)).await?;
        self.notify("initialized", json!({})).await
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

    async fn read_response_for_id(&self, id: i64) -> Result<Value> {
        loop {
            let resp = self.read_message().await?;
            // Skip notifications (they have no `id`).
            if response_matches_id(&resp, id) {
                return response_result(resp);
            }
        }
    }

    pub async fn notify(&self, method: &str, params: Value) -> Result<()> {
        let body = notification_body(method, params);
        self.write_message(&body).await
    }

    async fn write_message(&self, body: &Value) -> Result<()> {
        let message = framed_lsp_message(body)?;
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(&message).await?;
        stdin.flush().await?;
        Ok(())
    }

    async fn read_message(&self) -> Result<Value> {
        let mut stdout = self.stdout.lock().await;
        let len = read_content_length(&mut stdout).await?;
        read_json_body(&mut stdout, len).await
    }
}

fn clangd_command(repo: &std::path::Path) -> Command {
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

fn take_child_stdin(child: &mut Child) -> Result<ChildStdin> {
    child.stdin.take().context("clangd stdin missing")
}

fn take_child_stdout(child: &mut Child) -> Result<ChildStdout> {
    child.stdout.take().context("clangd stdout missing")
}

fn initialize_params(root: &std::path::Path) -> Value {
    json!({
        "processId": std::process::id(),
        "rootUri": format!("file://{}", root.display()),
        "capabilities": {},
        "clientInfo": { "name": "kuzushi-mcp-clang", "version": env!("CARGO_PKG_VERSION") }
    })
}

fn request_body(id: i64, method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
}

fn notification_body(method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
}

fn framed_lsp_message(body: &Value) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(body)?;
    Ok(frame_raw_lsp_message(raw))
}

fn frame_raw_lsp_message(raw: Vec<u8>) -> Vec<u8> {
    let mut message = format!("Content-Length: {}\r\n\r\n", raw.len()).into_bytes();
    message.extend(raw);
    message
}

fn response_matches_id(response: &Value, id: i64) -> bool {
    response.get("id") == Some(&json!(id))
}

fn response_result(response: Value) -> Result<Value> {
    if let Some(err) = response.get("error") {
        anyhow::bail!("clangd error: {err}");
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

async fn read_content_length<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<usize> {
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

enum HeaderLine {
    End,
    Field(String),
}

async fn read_header_line<R: AsyncRead + Unpin>(
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

fn header_line_from_bytes(buf: &[u8]) -> Result<HeaderLine> {
    let line = std::str::from_utf8(buf)?.trim_end_matches(['\r', '\n']);
    Ok(classify_header_line(line))
}

fn classify_header_line(line: &str) -> HeaderLine {
    if line.is_empty() {
        HeaderLine::End
    } else {
        HeaderLine::Field(line.to_string())
    }
}

fn record_content_length(content_length: &mut Option<usize>, line: &str) {
    if let Some(len) = content_length_value(line) {
        *content_length = Some(len);
    }
}

fn content_length_value(line: &str) -> Option<usize> {
    let rest = line
        .strip_prefix("Content-Length:")
        .or_else(|| line.strip_prefix("content-length:"))?;
    rest.trim().parse().ok()
}

async fn read_json_body<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    len: usize,
) -> Result<Value> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

async fn read_until_crlf<R: AsyncRead + Unpin>(
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
        if buf.ends_with(b"\r\n") {
            return Ok(buf.len());
        }
    }
}

/// Decode an LSP `Location` (or `Location[]`) JSON shape into
/// `(file, line, column)` triples.
#[derive(Debug, Clone, Deserialize)]
struct LspLocation {
    uri: String,
    range: LspRange,
}

#[derive(Debug, Clone, Deserialize)]
struct LspRange {
    start: LspPosition,
    #[allow(dead_code)]
    end: LspPosition,
}

#[derive(Debug, Clone, Deserialize)]
struct LspPosition {
    line: u32,
    character: u32,
}

pub fn parse_locations(value: &Value) -> Vec<(String, u32, u32)> {
    fn one(loc: &LspLocation) -> Option<(String, u32, u32)> {
        let path = loc
            .uri
            .strip_prefix("file://")
            .unwrap_or(&loc.uri)
            .to_string();
        // LSP positions are 0-based; Kuzushi schema is 1-based.
        Some((
            path,
            loc.range.start.line + 1,
            loc.range.start.character + 1,
        ))
    }

    if value.is_null() {
        return Vec::new();
    }
    if let Ok(single) = serde_json::from_value::<LspLocation>(value.clone()) {
        return one(&single).into_iter().collect();
    }
    if let Ok(many) = serde_json::from_value::<Vec<LspLocation>>(value.clone()) {
        return many.iter().filter_map(one).collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use serde_json::json;

    #[test]
    fn parse_locations_handles_single_object() {
        let v = json!({
            "uri": "file:///repo/a.c",
            "range": {
                "start": {"line": 10, "character": 5},
                "end": {"line": 10, "character": 14}
            }
        });
        let locs = parse_locations(&v);
        assert_eq!(locs, vec![("/repo/a.c".to_string(), 11, 6)]);
    }

    #[test]
    fn parse_locations_handles_array() {
        let v = json!([
            {"uri":"file:///r/a.c","range":{"start":{"line":0,"character":0},"end":{"line":0,"character":1}}},
            {"uri":"file:///r/b.c","range":{"start":{"line":4,"character":2},"end":{"line":4,"character":7}}}
        ]);
        let locs = parse_locations(&v);
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[0].1, 1);
        assert_eq!(locs[1].1, 5);
        assert_eq!(locs[1].2, 3);
    }

    #[test]
    fn parse_locations_handles_null_and_empty() {
        assert!(parse_locations(&json!(null)).is_empty());
        assert!(parse_locations(&json!([])).is_empty());
    }

    #[test]
    fn message_helpers_build_json_rpc_frames_and_results() {
        let body = request_body(7, "textDocument/hover", json!({"x":1}));
        assert_eq!(body["id"], json!(7));
        assert_eq!(body["method"], json!("textDocument/hover"));

        let framed = frame_raw_lsp_message(br#"{"ok":true}"#.to_vec());
        assert!(framed.starts_with(b"Content-Length: 11\r\n\r\n"));

        let result = response_result(json!({"id":7,"result":{"ok":true}})).unwrap();
        assert_eq!(result, json!({"ok":true}));
        assert!(response_result(json!({"id":7,"error":{"message":"bad"}})).is_err());
        assert!(response_matches_id(&json!({"id":7}), 7));
    }

    #[test]
    fn content_length_parsing_accepts_case_variants() {
        assert_eq!(content_length_value("Content-Length: 42"), Some(42));
        assert_eq!(content_length_value("content-length: 7"), Some(7));
        assert_eq!(content_length_value("X-Other: 7"), None);
    }

    #[tokio::test]
    async fn lsp_header_reader_extracts_content_length_and_body() {
        let payload = br#"{"jsonrpc":"2.0","id":1,"result":null}"#;
        let raw = format!(
            "Content-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            payload.len(),
            std::str::from_utf8(payload).unwrap()
        );
        let mut reader = BufReader::new(Cursor::new(raw.into_bytes()));

        let len = read_content_length(&mut reader).await.unwrap();
        assert_eq!(len, payload.len());
        let body = read_json_body(&mut reader, len).await.unwrap();
        assert_eq!(body["id"], json!(1));
    }

    #[tokio::test]
    async fn read_until_crlf_returns_partial_line_at_eof() {
        let mut reader = BufReader::new(Cursor::new(b"partial".to_vec()));
        let mut line = Vec::new();
        let n = read_until_crlf(&mut reader, &mut line).await.unwrap();
        assert_eq!(n, "partial".len());
        assert_eq!(line, b"partial");
    }
}
