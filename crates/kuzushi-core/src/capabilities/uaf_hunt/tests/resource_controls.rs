use super::*;
use crate::capabilities::uaf_hunt::adapters::clang_subprocess::ClangMcpClient;
use std::time::{Duration, Instant};

fn helper(root: &std::path::Path, call_body: &str, startup: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("owned-clang-helper.py");
    let program = format!(
        r#"#!/usr/bin/env python3
import json,sys,time
{startup}
for line in sys.stdin:
    request=json.loads(line)
    if request['method']=='shutdown':
        break
    if request['method']=='initialize':
        result={{}}
    elif request['method']=='tools/list':
        result={{'tools':[{{'name':name,'inputSchema':{{'properties':{{'compileCommandsPath':{{'type':'string'}}}}}}}} for name in ['clang.definition','clang.references','clang.type_at','clang.callers','clang.callees']]}}
    elif request['method']=='tools/call' and request['params']['name']=='clang.health':
        result={{'structuredContent':{{'ready':True,'missing':[]}}}}
    else:
{call_body}
    print(json.dumps({{'jsonrpc':'2.0','id':request['id'],'result':result}}),flush=True)
"#
    );
    std::fs::write(&path, program).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn clean_final() -> AgentLoopStep {
    AgentLoopStep::Final {
        text: String::new(),
        structured: Some(json!({"findings":[]})),
        cost_usd: None,
    }
}

fn owned_compile_db(root: &std::path::Path) {
    std::fs::write(root.join("compile_commands.json"), "[]").unwrap();
    std::fs::write(
        root.join("owned.c"),
        "// Owned source metadata, never executed.\n",
    )
    .unwrap();
}

#[test]
fn canceled_uaf_does_not_launch_a_helper_or_consume_a_step() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    owned_compile_db(root.path());
    let marker = root.path().join("helper-started");
    let startup = format!("open({},'w').close()", json!(marker.to_str().unwrap()));
    let binary = helper(root.path(), "        result={}", &startup);
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    let runtime = ScriptedUafRuntime::new(vec![clean_final()]);
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: Some(&cancellation),
        authorization: Default::default(),
    };
    let result = run_uaf_hunt_report(&json!({"target":root.path()}), &ctx, Some(&runtime));
    assert!(result.is_err(), "canceled work cannot complete");
    assert!(!marker.exists());
    assert_eq!(runtime.steps.lock().unwrap().len(), 1);
}

#[test]
fn configured_clang_deadline_stops_a_late_response() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    owned_compile_db(root.path());
    let binary = helper(root.path(), "        time.sleep(6)\n        result={}", "");
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    let runtime = ScriptedUafRuntime::new(vec![
        AgentLoopStep::ToolCall {
            call: ToolCall {
                name: "clang_definition".into(),
                input: json!({"file":"owned.c","line":1,"column":1}),
                call_id: "owned-call".into(),
            },
            cost_usd: None,
        },
        clean_final(),
    ]);
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let started = Instant::now();
    let result = run_uaf_hunt_report(
        &json!({"target":root.path(),"clangTimeoutSecs":5}),
        &ctx,
        Some(&runtime),
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_millis(5800));
    assert!(result.first_clang_error.unwrap().contains("timed out"));
}

#[test]
fn excessive_clang_response_is_rejected_before_it_enters_history() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    owned_compile_db(root.path());
    let binary = helper(
        root.path(),
        "        result={'structuredContent':{'text':'x'*(2*1024*1024)}}",
        "",
    );
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    let mut client = ClangMcpClient::spawn(
        root.path(),
        &root.path().join("compile_commands.json"),
        Duration::from_secs(1),
        None,
    )
    .unwrap();
    let result = client.call_tool("clang.definition", json!({}));
    assert!(
        result.is_err(),
        "excessive MCP output must fail without echoing its body"
    );
    let error = result.unwrap_err();
    assert!(format!("{error:#}").contains("byte limit"));
}

fn spawn_client(
    root: &std::path::Path,
    deadline: Duration,
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<ClangMcpClient> {
    owned_compile_db(root);
    ClangMcpClient::spawn(
        root,
        &root.join("compile_commands.json"),
        deadline,
        cancellation,
    )
}

#[test]
fn handshake_and_blocked_writes_share_the_configured_deadline() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    let binary = helper(root.path(), "        result={}", "time.sleep(2)");
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", &binary);
    let started = Instant::now();
    assert!(spawn_client(root.path(), Duration::from_millis(50), None).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    helper(root.path(), "        result={}", "");
    let script = std::fs::read_to_string(&binary).unwrap().replace(
        "flush=True)\n",
        "flush=True)\n    if request['method']=='tools/call' and request['params']['name']=='clang.health': time.sleep(2)\n",
    );
    std::fs::write(&binary, script).unwrap();
    let mut client = spawn_client(root.path(), Duration::from_millis(500), None).unwrap();
    let started = Instant::now();
    let error = client
        .call_tool("clang.definition", json!({"padding":"x".repeat(256*1024)}))
        .unwrap_err();
    assert!(format!("{error:#}").contains("timed out"));
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert!(format!(
        "{:#}",
        client.call_tool("clang.definition", json!({})).unwrap_err()
    )
    .contains("stopped"));
}

#[test]
fn cancellation_stops_an_active_clang_request() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    let binary = helper(root.path(), "        time.sleep(2)\n        result={}", "");
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    let cancellation = crate::scan::ScanCancellation::default();
    let mut client =
        spawn_client(root.path(), Duration::from_secs(1), Some(&cancellation)).unwrap();
    let token = cancellation.clone();
    let canceler = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        token.cancel();
    });
    let started = Instant::now();
    let error = client.call_tool("clang.definition", json!({})).unwrap_err();
    canceler.join().unwrap();
    assert!(format!("{error:#}").contains("canceled"));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn unsolicited_messages_have_count_and_cumulative_byte_bounds() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    for (startup, expected) in [
        ("for _ in range(80): print(json.dumps({'jsonrpc':'2.0','method':'owned-note'}),flush=True)", "skipped-message limit"),
        ("for _ in range(40): print(json.dumps({'jsonrpc':'2.0','method':'owned-note','text':'x'*40000}),flush=True)", "cumulative response byte limit"),
    ] {
        let binary = helper(root.path(), "        result={}", startup);
        let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
        let result = spawn_client(root.path(), Duration::from_secs(2), None);
        assert!(result.is_err());
        assert!(format!("{:#}", result.err().unwrap()).contains(expected));
    }
}

#[test]
fn stderr_cannot_fill_an_undrained_pipe() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    let binary = helper(
        root.path(),
        "        result={}",
        "sys.stderr.write('x'*(2*1024*1024));sys.stderr.flush()",
    );
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    let mut client = spawn_client(root.path(), Duration::from_secs(2), None).unwrap();
    assert!(client.call_tool("clang.definition", json!({})).is_ok());
}

#[test]
fn repository_failure_is_partial_in_both_report_and_finding_history() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    owned_compile_db(root.path());
    let binary = helper(root.path(), "        result={}", "");
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    let call = |name, input, id: &str| AgentLoopStep::ToolCall {
        call: ToolCall {
            name,
            input,
            call_id: id.into(),
        },
        cost_usd: None,
    };
    let runtime = ScriptedUafRuntime::new(vec![
        call(
            "clang_definition".into(),
            json!({"file":"owned.c","line":1,"column":1}),
            "navigation",
        ),
        call(
            "read_file".into(),
            json!({"file":"missing-owned.c"}),
            "missing-source",
        ),
        clean_final(),
    ]);
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = crate::findings::FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let trace = TraceHandle::jsonl(root.path(), "owned-uaf-partial");
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    let report = run_uaf_hunt_report(&json!({}), &ctx, Some(&runtime)).unwrap();
    assert_eq!(report.repo_tool_calls, 1);
    let error = report.first_repo_error.as_deref().unwrap();
    assert!(error.contains("read_file:"), "{error}");
    assert!(error.contains("missing-owned.c"), "{error}");
    assert!(report.is_partial());
    assert_eq!(
        store.run_status("owned-uaf-partial").unwrap().as_deref(),
        Some("partial")
    );
    assert!(store
        .list_findings_for_scan_id("owned-uaf-partial")
        .unwrap()
        .is_empty());
    assert!(
        std::path::Path::new(report.persisted.unwrap().transcript_path.as_ref().unwrap()).exists()
    );
}

#[test]
fn blank_protocol_lines_are_skipped_within_the_same_bounds() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    let binary = helper(
        root.path(),
        "        result={}",
        "print(chr(10)*8,flush=True)",
    );
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    if let Err(error) = spawn_client(root.path(), Duration::from_secs(2), None) {
        panic!("blank lines must not break the handshake: {error:#}");
    }
}

#[test]
fn healthy_drop_has_a_bounded_shutdown_grace() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    let binary = helper(root.path(), "        result={}", "");
    let program = std::fs::read_to_string(&binary).unwrap().replace(
        "    if request['method']=='shutdown':\n        break",
        "    if request['method']=='shutdown':\n        time.sleep(2)\n        break",
    );
    std::fs::write(&binary, program).unwrap();
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    let client = spawn_client(root.path(), Duration::from_secs(2), None).unwrap();
    let started = Instant::now();
    drop(client);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn selected_compile_database_is_frozen_and_bound_to_navigation() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    let source = root.path().join("chosen-build.json");
    std::fs::write(&source, serde_json::to_vec(&json!([{
        "directory":".", "file":"owned.c", "arguments":["clang","-DOWNED_SELECTED=1","-c","owned.c"]
    }])).unwrap()).unwrap();
    let binary = helper(
        root.path(),
        "        result={'structuredContent':{'arguments':request['params']['arguments']}}",
        "",
    );
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    let mut client =
        ClangMcpClient::spawn(root.path(), &source, Duration::from_secs(30), None).unwrap();
    let result = client
        .call_tool(
            "clang.definition",
            json!({"repoPath":root.path(),"file":"owned.c","line":1,"column":1}),
        )
        .unwrap();
    let bound = result["arguments"]["compileCommandsPath"]
        .as_str()
        .expect("the selected compile database must reach navigation");
    let prepared: serde_json::Value =
        serde_json::from_slice(&std::fs::read(bound).unwrap()).unwrap();
    assert_eq!(prepared[0]["arguments"][1], "-DOWNED_SELECTED=1");
    assert!(std::path::Path::new(prepared[0]["directory"].as_str().unwrap()).is_absolute());
    assert_ne!(std::path::Path::new(bound), source);
    std::fs::write(&source, "[]").unwrap();
    let again = client
        .call_tool(
            "clang.definition",
            json!({"repoPath":"/unselected","compileCommandsPath":source,"file":"owned.c","line":1,"column":1}),
        )
        .unwrap();
    assert_eq!(again["arguments"]["compileCommandsPath"], bound);
    assert_eq!(
        again["arguments"]["repoPath"],
        json!(std::fs::canonicalize(root.path()).unwrap())
    );
    assert_eq!(
        std::fs::read(bound).unwrap(),
        serde_json::to_vec(&prepared).unwrap()
    );
    let prepared_path = std::path::PathBuf::from(bound);
    drop(client);
    assert!(!prepared_path.exists());
}

#[test]
fn incompatible_compiler_helper_is_rejected_before_model_work() {
    let _guard = crate::test_env::mcp_clang_env_lock();
    let root = tempdir().unwrap();
    owned_compile_db(root.path());
    let binary = helper(root.path(), "        result={}", "");
    let program = std::fs::read_to_string(&binary)
        .unwrap()
        .replace("compileCommandsPath", "legacyPath");
    std::fs::write(&binary, program).unwrap();
    let _binary = crate::test_env::ScopedEnv::set("KUZUSHI_MCP_CLANG_BIN", binary);
    let runtime = ScriptedUafRuntime::new(vec![clean_final()]);
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let error =
        run_uaf_hunt_report(&json!({"target":root.path()}), &ctx, Some(&runtime)).unwrap_err();
    assert!(format!("{error:#}").contains("cannot bind the selected compiler database"));
    assert_eq!(runtime.steps.lock().unwrap().len(), 1);
}
