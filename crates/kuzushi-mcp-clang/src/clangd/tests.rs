#[cfg(test)]
mod tests {
    use super::super::*;
    use std::io::Cursor;

    use serde_json::json;
    use tokio::io::BufReader;

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
