#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::tool::{Tool, ToolHandler};
    use anyhow::Result;
    use async_trait::async_trait;
    use std::io::Cursor;

    struct EchoHandler;

    #[async_trait]
    impl ToolHandler for EchoHandler {
        async fn call(&self, args: Value) -> Result<Value> {
            Ok(json!({ "echoed": args }))
        }
    }

    fn make_registry() -> ToolRegistry {
        ToolRegistry::new().register(
            Tool {
                name: "echo".to_string(),
                description: "Echo args back.".to_string(),
                input_schema: json!({ "type": "object" }),
            },
            EchoHandler,
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
}
