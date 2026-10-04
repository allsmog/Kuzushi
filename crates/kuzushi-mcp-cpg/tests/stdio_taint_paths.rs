//! Drives the real `kuzushi-mcp-cpg` binary over stdio, the way the agent
//! bridge does, and checks that a TypeScript request-to-query flow comes back.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct McpSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl McpSession {
    fn start(root: &std::path::Path) -> Self {
        let roots = serde_json::to_string(&[std::fs::canonicalize(root).unwrap()]).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_kuzushi-mcp-cpg"))
            .env("KUZUSHI_MCP_READ_ROOTS", roots)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut session = Self {
            child,
            stdin,
            stdout,
        };
        session.request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"}
            }),
        );
        session.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        session
    }

    fn send(&mut self, message: Value) {
        writeln!(self.stdin, "{message}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "server closed stdout"
            );
            if let Ok(message) = serde_json::from_str::<Value>(&line) {
                if message["id"] == json!(id) {
                    return message;
                }
            }
        }
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn method_positions_disclose_approximation_and_reaching_defs_reject_gaps() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("main.go"),
        "package main\nfunc handler(input string) {\n  run(input)\n}\n\nfunc other() {}\n",
    )
    .unwrap();
    let mut session = McpSession::start(temp.path());
    for (id, line) in [(2, 3), (4, 5), (6, 30)] {
        let response = session.request(
            id,
            "tools/call",
            json!({"name":"cpg.method_at",
            "arguments":{"file":"main.go","line":line}}),
        );
        let result = &response["result"]["structuredContent"];
        assert_eq!(result["matchQuality"], "nearest-preceding", "{response}");
        assert_eq!(result["exactContainment"], false);
    }
    let response = session.request(
        8,
        "tools/call",
        json!({"name":"cpg.reaching_def",
        "arguments":{"file":"main.go","line":5,"var":"input"}}),
    );
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(response
        .to_string()
        .contains("exact method membership unavailable"));
}

#[test]
fn structural_numeric_limits_reject_overflow_and_wrong_types() {
    let temp = tempfile::tempdir().unwrap();
    let mut session = McpSession::start(temp.path());
    for (index, depth) in [json!(-1), json!(33), json!(u64::MAX), json!(1.5)]
        .into_iter()
        .enumerate()
    {
        let response = session.request(
            index as u64 + 2,
            "tools/call",
            json!({"name":"cpg.slice","arguments":{"method":"fn","line":1,"depth":depth}}),
        );
        assert!(
            response["error"].is_object() || response["result"]["isError"] == true,
            "{response}"
        );
        assert!(
            response.to_string().contains("invalid arguments"),
            "{response}"
        );
        assert!(response["result"]["structuredContent"].is_null());
    }
    let response = session.request(
        9,
        "tools/call",
        json!({"name":"cpg.method_at",
        "arguments":{"file":"file.go","line":u64::MAX}}),
    );
    assert!(
        response["error"].is_object() || response["result"]["isError"] == true,
        "{response}"
    );
    assert!(
        response.to_string().contains("invalid arguments"),
        "{response}"
    );
    assert!(response["result"]["structuredContent"].is_null());
}

#[test]
fn ambiguous_symbols_and_paths_return_candidates_and_accept_canonical_selectors() {
    let temp = tempfile::tempdir().unwrap();
    for package in ["one", "two"] {
        let directory = temp.path().join(package);
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("shared.go"),
            format!("package {package}\nfunc duplicate() {{\n  {package}()\n}}\n"),
        )
        .unwrap();
    }
    let mut session = McpSession::start(temp.path());
    let definitions = session.request(
        2,
        "tools/call",
        json!({"name":"cpg.definitions", "arguments":{"fn":"duplicate"}}),
    );
    let matches = definitions["result"]["structuredContent"]["matches"]
        .as_array()
        .unwrap();
    assert_eq!(matches.len(), 2);
    let response = session.request(
        3,
        "tools/call",
        json!({"name":"cpg.callees_of", "arguments":{"fn":"duplicate"}}),
    );
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(response.to_string().contains("ambiguous method"));
    let response = session.request(
        4,
        "tools/call",
        json!({"name":"cpg.method_at", "arguments":{"file":"shared.go","line":3}}),
    );
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(response.to_string().contains("ambiguous file"));
    let response = session.request(
        5,
        "tools/call",
        json!({"name":"cpg.callees_of", "arguments":{"fn":matches[0]["selector"]}}),
    );
    assert_eq!(
        response["result"]["structuredContent"]["callees"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "{response}"
    );
}

#[test]
fn taint_paths_reports_a_typescript_request_to_query_flow() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("users.ts"),
        "function list(req, res) {\n  const id = req.query.id;\n  db.query(\"SELECT \" + id);\n}\n",
    )
    .unwrap();
    let mut session = McpSession::start(temp.path());

    let response = session.request(
        2,
        "tools/call",
        json!({"name": "cpg.taint_paths", "arguments": {"source": "query", "sink": "^query$"}}),
    );

    let paths = &response["result"]["structuredContent"]["paths"];
    assert!(paths["flowCount"].as_u64().unwrap() >= 1, "{response}");
    let flow = &paths["flows"][0];
    assert_eq!(flow["language"], "typescript");
    assert!(flow["sinkFile"].as_str().unwrap().ends_with("users.ts"));
    assert_eq!(flow["sinkLine"], 3);
}
