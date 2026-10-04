use std::io;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::jsonrpc::{
    JsonRpcRequest, JsonRpcResponse, ERROR_INTERNAL, ERROR_INVALID_REQUEST, ERROR_PARSE,
};
use crate::tool::ToolRegistry;

use super::ServerInfo;

pub(crate) const MAX_JSONRPC_REQUEST_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_JSONRPC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

pub(super) enum Frame {
    EndOfStream,
    Message(Vec<u8>),
    Oversized,
}

pub async fn serve_stdio(info: ServerInfo, registry: ToolRegistry) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    serve_streams(info, registry, stdin, stdout).await
}

pub async fn serve_streams<R, W>(
    info: ServerInfo,
    registry: ToolRegistry,
    reader: R,
    mut writer: W,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut requests = super::lifecycle::Requests::default();
    loop {
        let frame = requests.next_frame(&mut reader, &mut writer).await?;
        if matches!(frame, Frame::EndOfStream) {
            return requests.drain(&mut writer).await;
        }
        if !requests
            .accept(frame, &info, &registry, &mut writer)
            .await?
        {
            return Ok(());
        }
    }
}

pub(super) fn oversized_request_response() -> JsonRpcResponse {
    JsonRpcResponse::err(
        Value::Null,
        ERROR_INVALID_REQUEST,
        format!("JSON-RPC request exceeds the {MAX_JSONRPC_REQUEST_BYTES}-byte frame limit"),
    )
}

struct ReadChunk {
    payload_bytes: usize,
    consumed_bytes: usize,
    terminates_frame: bool,
}

impl ReadChunk {
    fn from_available(available: &[u8]) -> Self {
        let newline = available.iter().position(|byte| *byte == b'\n');
        Self {
            payload_bytes: newline.unwrap_or(available.len()),
            consumed_bytes: newline.map_or(available.len(), |offset| offset.saturating_add(1)),
            terminates_frame: newline.is_some(),
        }
    }
}

pub(super) async fn read_frame<R>(reader: &mut R) -> io::Result<Frame>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(frame_at_eof(frame, oversized));
        }
        let chunk = ReadChunk::from_available(available);
        oversized = extend_request_frame(&mut frame, &available[..chunk.payload_bytes], oversized);
        reader.consume(chunk.consumed_bytes);
        if chunk.terminates_frame {
            return Ok(frame_at_boundary(frame, oversized));
        }
    }
}

fn extend_request_frame(frame: &mut Vec<u8>, bytes: &[u8], oversized: bool) -> bool {
    if oversized {
        return true;
    }
    append_within_request_budget(frame, bytes)
}

fn append_within_request_budget(frame: &mut Vec<u8>, bytes: &[u8]) -> bool {
    let within_budget = frame
        .len()
        .checked_add(bytes.len())
        .is_some_and(|length| length <= MAX_JSONRPC_REQUEST_BYTES);
    if within_budget {
        frame.extend_from_slice(bytes);
    }
    !within_budget
}

fn frame_at_eof(frame: Vec<u8>, oversized: bool) -> Frame {
    if oversized {
        Frame::Oversized
    } else if frame.is_empty() {
        Frame::EndOfStream
    } else {
        Frame::Message(frame)
    }
}

fn frame_at_boundary(frame: Vec<u8>, oversized: bool) -> Frame {
    if oversized {
        Frame::Oversized
    } else {
        Frame::Message(frame)
    }
}

pub(super) fn parse_jsonrpc_request(line: &str) -> Result<JsonRpcRequest, JsonRpcResponse> {
    serde_json::from_str(line).map_err(|err| {
        JsonRpcResponse::err(Value::Null, ERROR_PARSE, format!("parse error: {err}"))
    })
}

pub(super) fn response_for_request_result(
    id: Option<Value>,
    result: std::result::Result<Value, (i32, String)>,
) -> Option<JsonRpcResponse> {
    match (id, result) {
        (None, _) => None,
        (Some(id), Ok(value)) => Some(JsonRpcResponse::ok(id, value)),
        (Some(id), Err((code, msg))) => Some(JsonRpcResponse::err(id, code, msg)),
    }
}

pub(super) async fn write_jsonrpc_response<W>(
    writer: &mut W,
    response: JsonRpcResponse,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let id = response.id.clone();
    let encoded = match bounded_json_bytes(&response, MAX_JSONRPC_RESPONSE_BYTES)? {
        Some(encoded) => encoded,
        None => {
            let bounded_error = JsonRpcResponse::err(
                id,
                ERROR_INTERNAL,
                format!(
                    "JSON-RPC response exceeds the {MAX_JSONRPC_RESPONSE_BYTES}-byte frame limit"
                ),
            );
            bounded_json_bytes(&bounded_error, MAX_JSONRPC_RESPONSE_BYTES)?
                .ok_or_else(|| anyhow::anyhow!("bounded JSON-RPC error response exceeded limit"))?
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        writer.write_all(&encoded).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    })
    .await??;
    Ok(())
}

pub fn bounded_json_bytes<T>(value: &T, limit: usize) -> Result<Option<Vec<u8>>>
where
    T: Serialize,
{
    let mut writer = BoundedJsonWriter::new(limit);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(Some(writer.bytes)),
        Err(_) if writer.exceeded => Ok(None),
        Err(error) => Err(error.into()),
    }
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8 * 1024)),
            limit,
            exceeded: false,
        }
    }
}

impl io::Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let fits = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_some_and(|length| length <= self.limit);
        if !fits {
            self.exceeded = true;
            return Err(io::Error::other("JSON serialization budget exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
