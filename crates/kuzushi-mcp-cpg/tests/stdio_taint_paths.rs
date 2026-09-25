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
