//! Bounded, cancellable request execution while frame intake remains responsive.
use super::transport::{
    oversized_request_response, parse_jsonrpc_request, read_frame, response_for_request_result,
    write_jsonrpc_response, Frame,
};
use super::{dispatch::dispatch, ServerInfo};
use crate::{
    jsonrpc::{JsonRpcRequest, JsonRpcResponse, ERROR_INVALID_REQUEST, ERROR_PARSE},
    tool::ToolRegistry,
};
use anyhow::Result;
use futures::{
    future::{AbortHandle, Abortable, BoxFuture},
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use serde_json::Value;
use std::collections::HashMap;
use tokio::io::{AsyncBufRead, AsyncWrite};

const MAX_IN_FLIGHT: usize = 8;
type Completion = (Option<String>, Option<JsonRpcResponse>);

#[derive(Default)]
pub(super) struct Requests<'a> {
    pending: FuturesUnordered<BoxFuture<'a, Completion>>,
    cancellations: HashMap<String, AbortHandle>,
}

impl<'a> Requests<'a> {
    pub(super) async fn next_frame<R, W>(&mut self, reader: &mut R, writer: &mut W) -> Result<Frame>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        // Keep this future pinned across request completions: read_frame owns
        // partial bytes and must not be restarted by select cancellation.
        let frame = read_frame(reader);
        tokio::pin!(frame);
        loop {
            tokio::select! {
                frame = &mut frame => return Ok(frame?),
                Some(completion) = self.pending.next(), if !self.pending.is_empty() => {
                    self.complete(completion, writer).await?;
                }
            }
        }
    }

    pub(super) async fn accept<W>(
        &mut self,
        frame: Frame,
        info: &'a ServerInfo,
        registry: &'a ToolRegistry,
        writer: &mut W,
    ) -> Result<bool>
    where
        W: AsyncWrite + Unpin,
    {
        let request = match parse_frame(frame) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(true),
            Err(response) => {
                write_jsonrpc_response(writer, response).await?;
                return Ok(true);
            }
        };
        match request.method.as_str() {
            "notifications/cancelled" => self.cancel(&request),
            "shutdown" | "exit" => {
                self.shutdown(request, writer).await?;
                return Ok(false);
            }
            _ => {
                if let Some(response) = self.enqueue(request, info, registry) {
                    write_jsonrpc_response(writer, response).await?;
                }
            }
        }
        Ok(true)
    }

    fn enqueue(
        &mut self,
        request: JsonRpcRequest,
        info: &'a ServerInfo,
        registry: &'a ToolRegistry,
    ) -> Option<JsonRpcResponse> {
        let id = request.id.clone();
        let key = id.as_ref().map(Value::to_string);
        if self.pending.len() >= MAX_IN_FLIGHT
            || key
                .as_ref()
                .is_some_and(|key| self.cancellations.contains_key(key))
        {
            return id.map(|id| {
                JsonRpcResponse::err(
                    id,
                    ERROR_INVALID_REQUEST,
                    "request limit reached or duplicate active request ID",
                )
            });
        }
        let (abort, registration) = AbortHandle::new_pair();
        if let Some(key) = &key {
            self.cancellations.insert(key.clone(), abort);
        }
        self.pending.push(
            async move {
                let result = Abortable::new(dispatch(&request, info, registry), registration).await;
                let result = result.unwrap_or_else(|_| Err((-32800, "request cancelled".into())));
                (key, response_for_request_result(id, result))
            }
            .boxed(),
        );
        None
    }

    fn cancel(&self, request: &JsonRpcRequest) {
        let Some(id) = request
            .params
            .as_ref()
            .and_then(|params| params.get("requestId"))
        else {
            return;
        };
        if let Some(abort) = self.cancellations.get(&id.to_string()) {
            abort.abort();
        }
    }

    async fn complete<W: AsyncWrite + Unpin>(
        &mut self,
        completion: Completion,
        writer: &mut W,
    ) -> Result<()> {
        if let Some(key) = completion.0 {
            self.cancellations.remove(&key);
        }
        if let Some(response) = completion.1 {
            write_jsonrpc_response(writer, response).await?;
        }
        Ok(())
    }

    async fn shutdown<W: AsyncWrite + Unpin>(
        &mut self,
        request: JsonRpcRequest,
        writer: &mut W,
    ) -> Result<()> {
        self.pending.clear();
        self.cancellations.clear();
        if let Some(id) = request.id {
            write_jsonrpc_response(writer, JsonRpcResponse::ok(id, Value::Null)).await?;
        }
        Ok(())
    }

    pub(super) async fn drain<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<()> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while !self.pending.is_empty() {
            let completion = tokio::time::timeout_at(deadline, self.pending.next()).await?;
            if let Some(completion) = completion {
                self.complete(completion, writer).await?;
            }
        }
        Ok(())
    }
}

fn parse_frame(frame: Frame) -> Result<Option<JsonRpcRequest>, JsonRpcResponse> {
    let bytes = match frame {
        Frame::EndOfStream => return Ok(None),
        Frame::Oversized => return Err(oversized_request_response()),
        Frame::Message(bytes) => bytes,
    };
    let message = std::str::from_utf8(&bytes)
        .map_err(|_| JsonRpcResponse::err(Value::Null, ERROR_PARSE, "request is not UTF-8"))?
        .trim();
    if message.is_empty() {
        return Ok(None);
    }
    parse_jsonrpc_request(message).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::{Tool, ToolHandler};
    use async_trait::async_trait;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    struct LongRequest {
        started: Arc<tokio::sync::Notify>,
        dropped: Arc<AtomicBool>,
    }
    struct Lifetime(Arc<AtomicBool>);
    impl Drop for Lifetime {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    #[async_trait]
    impl ToolHandler for LongRequest {
        async fn call(&self, _: Value) -> Result<Value> {
            let _lifetime = Lifetime(self.dropped.clone());
            self.started.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancellation_drops_running_work_and_shutdown_stops_intake() {
        let started = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let registry = ToolRegistry::new().register(
            Tool {
                name: "long".into(),
                description: String::new(),
                input_schema: serde_json::json!({"type":"object"}),
            },
            LongRequest {
                started: started.clone(),
                dropped: dropped.clone(),
            },
        );
        let (client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let task = tokio::spawn(super::super::serve_streams(
            ServerInfo::new("test", "1"),
            registry,
            reader,
            writer,
        ));
        let (reader, mut writer) = tokio::io::split(client);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"long\",\"arguments\":{}}}\n").await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
            .await
            .unwrap();
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n").await.unwrap();
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reader.read_line(&mut line),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap()["error"]["code"],
            -32800
        );
        assert!(dropped.load(Ordering::SeqCst));
        writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"shutdown\"}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], 2);
        assert_eq!(reader.read_line(&mut String::new()).await.unwrap(), 0);
        task.await.unwrap().unwrap();
    }
}
