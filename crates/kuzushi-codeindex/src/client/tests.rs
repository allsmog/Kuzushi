#[cfg(test)]
mod tests {
    use super::super::*;

    /// Spawning a non-existent binary errors actionably.
    #[tokio::test]
    async fn spawn_missing_binary_errors() {
        let err = McpClient::spawn("kuzushi-no-such-mcp-binary-zzz")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("kuzushi-no-such-mcp-binary-zzz") || msg.contains("could not spawn"));
    }

    #[test]
    fn tool_call_result_prefers_structured_content_and_reports_errors() {
        assert_eq!(
            tool_call_params("clang.definition", json!({"file": "a.c"})),
            json!({"name": "clang.definition", "arguments": {"file": "a.c"}})
        );

        let structured = tool_call_result(
            "mcp",
            json!({
                "content": [{"text": "ignored"}],
                "structuredContent": {"ok": true}
            }),
        )
        .unwrap();
        assert_eq!(structured, json!({"ok": true}));

        let raw = tool_call_result("mcp", json!({"content": []})).unwrap();
        assert_eq!(raw, json!({"content": []}));

        let err = tool_call_result(
            "mcp",
            json!({"isError": true, "content": [{"text": "bad input"}]}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("mcp: bad input"));
    }

    #[test]
    fn response_matching_ignores_other_ids_and_extracts_errors_results_and_nulls() {
        assert_eq!(
            response_result_for_id("mcp", &json!({"id": 1, "result": {"ok": true}}), 2).unwrap(),
            None
        );
        assert_eq!(
            response_result_for_id("mcp", &json!({"id": 2, "result": {"ok": true}}), 2).unwrap(),
            Some(json!({"ok": true}))
        );
        assert_eq!(
            response_result_for_id("mcp", &json!({"id": 2}), 2).unwrap(),
            Some(Value::Null)
        );
        let err =
            response_result_for_id("mcp", &json!({"id": 2, "error": {"code": -1}}), 2).unwrap_err();
        assert!(err.to_string().contains("mcp"));
    }

    #[test]
    fn json_line_serializes_with_trailing_newline() {
        let raw = json_line(&json!({"jsonrpc": "2.0"})).unwrap();
        assert!(raw.ends_with(b"\n"));
        assert!(std::str::from_utf8(&raw).unwrap().contains("\"jsonrpc\""));
    }

    #[test]
    fn raw_line_helpers_parse_json_and_report_closed_server() {
        assert_eq!(
            parse_json_line("{\"ok\":true}\n").unwrap(),
            json!({"ok": true})
        );
        assert!(parse_json_line("{").is_err());
        assert!(ensure_server_line_read(1).is_ok());
        assert!(ensure_server_line_read(0)
            .unwrap_err()
            .to_string()
            .contains("exited"));
    }

    #[test]
    fn json_rpc_request_body_includes_id_method_and_params() {
        assert_eq!(
            json_rpc_request_body(7, "tools/list", json!({"cursor": null})),
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/list",
                "params": {"cursor": null}
            })
        );
    }
}
