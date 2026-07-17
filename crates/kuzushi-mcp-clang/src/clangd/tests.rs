#[cfg(test)]
mod tests {
    use super::super::*;
    use std::io::Cursor;

    use serde_json::json;
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::Stdio;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::BufReader;
    use tokio::process::Command;

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
    async fn duplicate_content_length_headers_are_rejected() {
        let raw = b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        let mut reader = BufReader::new(Cursor::new(raw));

        let error = read_content_length(&mut reader).await.unwrap_err();

        assert!(error.to_string().contains("duplicate Content-Length"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sandbox_blocks_absolute_include_paths_from_a_malicious_compile_database() {
        use kuzushi_mcp_common::process::{run_bounded_process, ProcessLimits};
        use kuzushi_mcp_common::read_only_sandbox::{read_only_command, sandbox_available};

        let outer = tempfile::tempdir().unwrap();
        let repo = outer.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let secret = outer.path().join("secret.h");
        std::fs::write(&secret, "#define HOST_SECRET 1\n").unwrap();
        std::fs::write(
            repo.join("compile_commands.json"),
            serde_json::to_vec(&json!([{
                "directory": repo,
                "file": "main.c",
                "arguments": ["clang", "-include", secret, "-c", "main.c"]
            }]))
            .unwrap(),
        )
        .unwrap();
        let capability = kuzushi_mcp_common::ReadRootCapability::new([repo.clone()]).unwrap();
        let input = capability.authorize_directory(&repo).unwrap();
        if !sandbox_available().await {
            assert!(
                read_only_command(Path::new("/bin/sh"), ["-c", "true"], input)
                    .await
                    .is_err()
            );
            return;
        }
        let script = "grep -F \"$1\" compile_commands.json >/dev/null && cat \"$1\"";
        let mut sandboxed = read_only_command(
            Path::new("/bin/sh"),
            [
                OsStr::new("-c"),
                OsStr::new(script),
                OsStr::new("fixture"),
                secret.as_os_str(),
            ],
            input,
        )
        .await
        .unwrap();
        let output = run_bounded_process(
            sandboxed.command_mut().unwrap(),
            "malicious compile database fixture",
            ProcessLimits {
                timeout: Duration::from_secs(2),
                stdout_bytes: 8 * 1024,
                stderr_bytes: 8 * 1024,
            },
        )
        .await
        .unwrap();

        assert!(!output.status.success());
        assert!(!output.stdout.contains("HOST_SECRET"));
    }

    #[tokio::test]
    async fn read_until_crlf_returns_partial_line_at_eof() {
        let mut reader = BufReader::new(Cursor::new(b"partial".to_vec()));
        let mut line = Vec::new();
        let n = read_until_crlf(&mut reader, &mut line).await.unwrap();
        assert_eq!(n, "partial".len());
        assert_eq!(line, b"partial");
    }

    #[cfg(unix)]
    #[test]
    fn file_uri_percent_encodes_special_and_non_ascii_path_bytes() {
        let uri = file_uri(std::path::Path::new("/tmp/a b#%é.c")).unwrap();

        assert_eq!(uri, "file:///tmp/a%20b%23%25%C3%A9.c");
    }

    #[cfg(windows)]
    #[test]
    fn file_uri_encodes_windows_drive_paths() {
        let uri = file_uri(std::path::Path::new(r"C:\work dir\a#b.c")).unwrap();

        assert_eq!(uri, "file:///C:/work%20dir/a%23b.c");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn request_gate_keeps_concurrent_response_ids_ordered() {
        let frames = format!(
            "{}{}",
            response_frame(1, json!("first")),
            response_frame(2, json!("second"))
        );
        let client = fixture_client(&frames).await;

        let (first, second) = tokio::join!(
            client.request("fixture/first", json!({})),
            client.request("fixture/second", json!({}))
        );

        assert_eq!(first.unwrap(), json!("first"));
        assert_eq!(second.unwrap(), json!("second"));
        client.kill_and_reap().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn queued_request_deadline_includes_time_waiting_for_the_gate() {
        let client = fixture_client("").await;
        let held_gate = client.request_gate.lock().await;
        let started = tokio::time::Instant::now();

        let error = client
            .request_with_timeout("fixture/queued", json!({}), Duration::from_millis(50))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!client.is_running().await);
        drop(held_gate);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn notification_flood_hits_the_skip_budget() {
        let mut frames = String::new();
        for index in 0..64 {
            frames.push_str(&notification_frame(index));
        }
        frames.push_str(&response_frame(1, json!("too late")));
        let client = fixture_client(&frames).await;

        let error = client
            .request_with_timeout("fixture/flood", json!({}), Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("unrelated messages"));
        assert!(!client.is_running().await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn notification_flood_hits_the_cumulative_byte_budget() {
        let client = generated_notification_fixture(5, 1024 * 1024).await;

        let error = client
            .request_with_timeout("fixture/flood", json!({}), Duration::from_secs(2))
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("cumulative limit"));
        assert!(!client.is_running().await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn silent_server_is_killed_at_the_request_deadline() {
        let client = fixture_client("").await;

        let error = client
            .request_with_timeout("fixture/silent", json!({}), Duration::from_millis(50))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("deadline"));
        assert!(!client.is_running().await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backpressured_notification_is_killed_at_its_deadline() {
        let client = fixture_client("").await;
        let payload = "x".repeat(1024 * 1024);

        let error = client
            .notify_with_timeout(
                "fixture/backpressure",
                json!({"payload": payload}),
                Duration::from_millis(50),
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("deadline"));
        assert!(!client.is_running().await);
    }

    #[cfg(unix)]
    async fn fixture_client(frames: &str) -> Arc<ClangdClient> {
        use std::os::unix::process::CommandExt;

        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("printf '%s' \"$KUZUSHI_LSP_FIXTURE\"; sleep 30")
            .env("KUZUSHI_LSP_FIXTURE", frames)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Arc::new(ClangdClient::from_child_io(child, stdin, stdout))
    }

    #[cfg(unix)]
    async fn generated_notification_fixture(
        count: usize,
        payload_bytes: usize,
    ) -> Arc<ClangdClient> {
        use std::os::unix::process::CommandExt;

        let prefix = r#"{"jsonrpc":"2.0","method":"fixture/progress","params":{"payload":""#;
        let suffix = r#""}}"#;
        let body_bytes = prefix.len() + payload_bytes + suffix.len();
        let script = format!(
            "i=0; while [ \"$i\" -lt {count} ]; do \
             printf 'Content-Length: {body_bytes}\\r\\n\\r\\n{prefix}'; \
             head -c {payload_bytes} /dev/zero | tr '\\0' x; \
             printf '{suffix}'; i=$((i + 1)); done; sleep 30"
        );
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Arc::new(ClangdClient::from_child_io(child, stdin, stdout))
    }

    fn response_frame(id: i64, result: serde_json::Value) -> String {
        frame(&json!({"jsonrpc":"2.0", "id":id, "result":result}))
    }

    fn notification_frame(index: usize) -> String {
        frame(&json!({"jsonrpc":"2.0", "method":"fixture/progress", "params":{"index":index}}))
    }

    fn frame(value: &serde_json::Value) -> String {
        let body = serde_json::to_string(value).unwrap();
        format!("Content-Length: {}\r\n\r\n{body}", body.len())
    }
}
