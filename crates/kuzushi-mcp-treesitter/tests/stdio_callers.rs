//! Drives the real `kuzushi-mcp-treesitter` binary over stdio and checks a
//! syntax-aware answer, the way the agent bridge would ask it.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn callers_finds_the_call_site_of_a_sink_wrapper() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("users.ts");
    std::fs::write(
        &file,
        "function run(sql) {\n  return db.query(sql);\n}\nfunction list(req) {\n  return run(req.query.id);\n}\n",
    )
    .unwrap();
    let roots = serde_json::to_string(&[std::fs::canonicalize(temp.path()).unwrap()]).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kuzushi-mcp-treesitter"))
        .env("KUZUSHI_MCP_READ_ROOTS", roots)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut request = |id: u64, method: &str, params: Value| -> Value {
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        )
        .unwrap();
        stdin.flush().unwrap();
        loop {
            let mut line = String::new();
            assert!(
                stdout.read_line(&mut line).unwrap() > 0,
                "server closed stdout"
            );
            if let Ok(message) = serde_json::from_str::<Value>(&line) {
                if message["id"] == json!(id) {
                    return message;
                }
            }
        }
    };
    request(
        1,
        "initialize",
        json!({"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
    );

    let response = request(
        2,
        "tools/call",
        json!({"name": "tree_sitter:callers", "arguments": {"file": file, "language": "typescript", "function": "run"}}),
    );
    let _ = child.kill();
    let _ = child.wait();

    let result = &response["result"]["structuredContent"];
    assert_eq!(response["result"]["isError"], json!(false), "{response}");
    assert_eq!(result["hit_count"], json!(1), "{response}");
    assert_eq!(result["hits"][0]["call"]["snippet"], "run(req.query.id)");
    assert_eq!(result["hits"][0]["call"]["start"]["row"], json!(5));
}
