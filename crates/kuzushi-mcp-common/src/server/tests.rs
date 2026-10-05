#[cfg(test)]
mod tests {
    use super::super::transport::{MAX_JSONRPC_REQUEST_BYTES, MAX_JSONRPC_RESPONSE_BYTES};
    use super::super::*;
    use crate::tool::{Tool, ToolHandler, ToolRegistry};
    use anyhow::Result;
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use std::io::Cursor;

    struct EchoHandler;
    struct OversizedHandler;

    #[async_trait]
    impl ToolHandler for EchoHandler {
        async fn call(&self, args: Value) -> Result<Value> {
            Ok(json!({ "echoed": args }))
        }
    }

    #[async_trait]
    impl ToolHandler for OversizedHandler {
        async fn call(&self, _args: Value) -> Result<Value> {
            Ok(json!({"payload": "x".repeat(MAX_JSONRPC_RESPONSE_BYTES)}))
        }
    }

    fn make_registry() -> ToolRegistry {
        ToolRegistry::new()
            .register(
                Tool {
                    name: "echo".to_string(),
                    description: "Echo args back.".to_string(),
                    input_schema: json!({ "type": "object" }),
                },
                EchoHandler,
            )
            .register(
                Tool {
                    name: "oversized".to_string(),
                    description: "Return a response over the transport budget.".to_string(),
                    input_schema: json!({ "type": "object" }),
                },
                OversizedHandler,
            )
    }

    async fn drive(input: &str) -> String {
        let info = ServerInfo::new("kuzushi-mcp-test", "0.0.0");
        let registry = make_registry();
        let reader = Cursor::new(input.as_bytes().to_vec());
        let mut output = Vec::new();
        serve_streams(info, registry, reader, &mut output)
            .await
            .unwrap();
        String::from_utf8(output).unwrap()
    }

    fn padded_frame(message: &str, frame_bytes: usize, newline: bool) -> String {
        assert!(message.len() <= frame_bytes);
        let mut frame = " ".repeat(frame_bytes - message.len());
        frame.push_str(message);
        if newline {
            frame.push('\n');
        }
        frame
    }

    #[tokio::test]
    async fn initialize_returns_protocol_version() {
        let out = drive("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n").await;
        assert!(out.contains("\"protocolVersion\":\"2024-11-05\""));
        assert!(out.contains("\"name\":\"kuzushi-mcp-test\""));
    }

    #[tokio::test]
    async fn tools_list_returns_registered_tools() {
        let out = drive("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n").await;
        assert!(out.contains("\"name\":\"echo\""));
    }

    #[tokio::test]
    async fn tools_call_dispatches_and_wraps_response() {
        let out = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"k\":1}}}\n",
        )
        .await;
        assert!(out.contains("\"isError\":false"));
        assert!(out.contains("\"echoed\""));
        // Both a text content block and structuredContent should be present.
        assert!(out.contains("\"structuredContent\""));
    }

    #[tokio::test]
    async fn omitted_arguments_are_empty_while_explicit_null_is_rejected() {
        let omitted = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"}}\n",
        ).await;
        assert!(omitted.contains("\"isError\":false"));
        assert!(omitted.contains("\"echoed\":{}"));
        let null = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":null}}\n",
        ).await;
        assert!(null.contains("\"isError\":true"));
    }

    #[tokio::test]
    async fn unknown_tool_returns_method_not_found() {
        let out = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"missing\"}}\n",
        )
        .await;
        assert!(out.contains("\"error\""));
        assert!(out.contains("-32601")); // method not found
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let out = drive("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"some/random\"}\n").await;
        assert!(out.contains("-32601"));
        assert!(out.contains("some/random"));
    }

    #[tokio::test]
    async fn parse_error_is_reported_with_null_id() {
        let out = drive("not json\n").await;
        assert!(out.contains("-32700")); // parse error
        assert!(out.contains("\"id\":null"));
    }

    #[tokio::test]
    async fn notification_produces_no_response() {
        let out = drive("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await;
        assert!(out.is_empty(), "notifications must not yield a response");
    }

    #[tokio::test]
    async fn empty_lines_are_skipped() {
        let out = drive("\n\n{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/list\"}\n\n").await;
        assert!(out.contains("\"name\":\"echo\""));
    }

    #[tokio::test]
    async fn exact_request_limit_is_accepted() {
        let message = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\"}";
        let input = padded_frame(message, MAX_JSONRPC_REQUEST_BYTES, true);

        let out = drive(&input).await;

        assert!(out.contains("\"id\":7"));
        assert!(out.contains("\"protocolVersion\""));
        assert!(!out.contains("frame limit"));
    }

    #[tokio::test]
    async fn oversized_newline_frame_is_drained_before_the_next_request() {
        let oversized = padded_frame("{}", MAX_JSONRPC_REQUEST_BYTES + 1, true);
        let valid = "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/list\"}\n";

        let out = drive(&format!("{oversized}{valid}")).await;

        let responses = out.lines().collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert!(responses[0].contains("-32600"));
        assert!(responses[0].contains("frame limit"));
        assert!(responses[1].contains("\"id\":8"));
        assert!(responses[1].contains("\"name\":\"echo\""));
    }

    #[tokio::test]
    async fn oversized_unterminated_frame_returns_a_stable_error() {
        let input = padded_frame("{}", MAX_JSONRPC_REQUEST_BYTES + 1, false);

        let out = drive(&input).await;

        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("-32600"));
        assert!(out.contains("frame limit"));
    }

    #[tokio::test]
    async fn oversized_tool_response_is_replaced_with_a_bounded_error() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"oversized\",\"arguments\":{}}}\n";

        let out = drive(input).await;

        assert!(out.len() < MAX_JSONRPC_RESPONSE_BYTES);
        assert!(out.contains("\"id\":9"));
        assert!(out.contains("-32603"));
        assert!(out.contains("response exceeds"));
        assert!(!out.contains(&"x".repeat(1024)));
    }
}
