use super::bridge_payloads::{
    BridgeRequest, NextStepBridgeRequest, LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
};
use super::bridge_process::{
    bridge_near_executable, configure_bridge_process_group, default_langgraph_bridge_command,
    mcp_binary_env_defaults, public_bridge_error, public_bridge_failure, read_bounded_pipe,
    run_next_step_bridge, wait_with_output_deadline_limits,
};
use kuzushi_core::AgentToolPolicy;
use serde_json::json;
use std::fs;
use std::io::Cursor;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::tempdir;

#[test]
fn bridge_pipe_reader_rejects_output_above_limit() {
    let mut output = Cursor::new(vec![b'x'; 17]);

    let error = read_bounded_pipe(&mut output, 16, "stdout")
        .unwrap_err()
        .to_string();

    assert!(error.contains("capture limit"), "{error}");
}

#[test]
fn bridge_output_overflow_kills_the_registered_process_tree() {
    let mut command = Command::new("node");
    command
        .args([
            "-e",
            "for (;;) require('node:fs').writeSync(1, '1234567890')",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_bridge_process_group(&mut command);
    let child = command.spawn().unwrap();
    let started = Instant::now();

    let error = wait_with_output_deadline_limits(
        child,
        "bridge fixture",
        Duration::from_secs(5),
        None,
        16,
        16,
    )
    .unwrap_err()
    .to_string();

    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(error.contains("capture limit"), "{error}");
}

#[test]
fn default_langgraph_bridge_command_finds_bridge_in_source_root() {
    let tmp = tempdir().unwrap();
    let scripts = tmp.path().join("scripts");
    fs::create_dir_all(&scripts).unwrap();
    let bridge = scripts.join("langgraph-bridge.mjs");
    fs::write(&bridge, "/* test */").unwrap();

    let cmd = default_langgraph_bridge_command(tmp.path());
    assert_eq!(cmd[0], "node");
    assert_eq!(cmd[1], bridge.display().to_string());
}

#[test]
fn bridge_near_executable_walks_up_to_find_scripts_dir() {
    let tmp = tempdir().unwrap();
    let release = tmp.path().join("target").join("release");
    fs::create_dir_all(&release).unwrap();
    let exe = release.join("kuzushi");
    fs::write(&exe, b"#!/bin/sh\n").unwrap();
    let scripts = tmp.path().join("scripts");
    fs::create_dir_all(&scripts).unwrap();
    let bridge = scripts.join("langgraph-bridge.mjs");
    fs::write(&bridge, "/* test */").unwrap();

    let resolved = bridge_near_executable(&exe).expect("walks up to <root>/scripts");
    assert_eq!(resolved, bridge);
}

#[test]
fn bridge_near_executable_returns_none_when_absent() {
    let tmp = tempdir().unwrap();
    let exe = tmp.path().join("kuzushi");
    fs::write(&exe, b"#!/bin/sh\n").unwrap();
    assert!(bridge_near_executable(&exe).is_none());
}

#[test]
fn mcp_binary_env_defaults_finds_sibling_mcp_binaries() {
    let exe = std::env::current_exe().expect("test exe");
    let dir = exe.parent().expect("test exe has parent");
    let fake = dir.join("kuzushi-mcp-treesitter-test-fake");
    std::fs::write(&fake, b"#!/bin/sh\n").ok();

    let prior = std::env::var_os("KUZUSHI_MCP_TREESITTER_BIN");
    unsafe {
        std::env::remove_var("KUZUSHI_MCP_TREESITTER_BIN");
    }

    let defaults = mcp_binary_env_defaults();

    assert!(
        defaults.iter().all(|(_, path)| path.parent() == Some(dir)),
        "every default path must be a sibling of the test exe: {defaults:?}"
    );

    unsafe {
        std::env::set_var("KUZUSHI_MCP_TREESITTER_BIN", "/operator/override");
    }
    let with_override = mcp_binary_env_defaults();
    assert!(
        with_override
            .iter()
            .all(|(env_var, _)| *env_var != "KUZUSHI_MCP_TREESITTER_BIN"),
        "operator override should win: {with_override:?}"
    );

    restore_treesitter_bin_env(prior);
    let _ = std::fs::remove_file(&fake);
}

fn restore_treesitter_bin_env(prior: Option<std::ffi::OsString>) {
    unsafe {
        match prior {
            Some(v) => std::env::set_var("KUZUSHI_MCP_TREESITTER_BIN", v),
            None => std::env::remove_var("KUZUSHI_MCP_TREESITTER_BIN"),
        }
    }
}

#[test]
fn public_bridge_error_rewrites_internal_provider_tokens() {
    let error =
        "next-step: no OpenAI credentials for openai-codex. Set up kuzushi auth login openai-codex";

    let public = public_bridge_error(error);

    assert!(public.contains("OpenAI OAuth"));
    assert!(public.contains("kuzushi auth login openai"));
    assert!(!public.contains("openai-codex"));
}

#[test]
fn bridge_stderr_failure_rewrites_internal_provider_tokens() {
    let sentinel = "raw-provider-stderr-sentinel";
    let request = test_next_step_request();
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("printf '%s' '{sentinel}' >&2; exit 1"),
    ];

    let error = run_next_step_bridge(&command, &request, None)
        .unwrap_err()
        .to_string();

    assert!(error.contains("stdout/stderr details were suppressed"));
    assert!(!error.contains(sentinel));
}

#[test]
fn bridge_parse_failure_rewrites_internal_provider_tokens() {
    let request = test_next_step_request();
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        "printf '%s' 'malformed openai-codex response'".to_string(),
    ];

    let error = run_next_step_bridge(&command, &request, None)
        .unwrap_err()
        .to_string();

    assert!(error.contains("could not parse next-step bridge JSON response"));
    assert!(!error.contains("openai-codex"));
}

#[test]
fn public_bridge_error_suppresses_arbitrary_provider_content() {
    let sentinel = "raw-provider-body-and-model-response-sentinel";

    let public = public_bridge_error(sentinel);

    assert_eq!(
        public,
        "Bridge operation failed; raw error details were suppressed."
    );
    assert!(!public.contains(sentinel));
}

#[test]
fn structured_bridge_failure_ignores_arbitrary_fallback_content() {
    let sentinel = "raw-provider-body-sentinel";

    let public = public_bridge_failure(Some("rate_limited"), Some(429), Some(sentinel));

    assert_eq!(public, "Provider rate limited the request (HTTP 429).");
    assert!(!public.contains(sentinel));
}

#[test]
fn bridge_requests_serialize_protocol_version() {
    let request = BridgeRequest {
        protocol_version: LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
        model: "test-runtime-model".to_string(),
        cwd: ".".to_string(),
        system_prompt: "system".to_string(),
        prompt: "prompt".to_string(),
        structured_output: None,
        api_key_env: "OPENAI_API_KEY".to_string(),
        api_key: None,
        base_url: None,
        thinking_level: None,
        max_output_tokens: None,
        tool_policy: AgentToolPolicy::default(),
        runtime_options: None,
        temperature: None,
    };

    let value = serde_json::to_value(request).unwrap();

    assert_eq!(
        value.pointer("/protocolVersion"),
        Some(&json!(LANGGRAPH_BRIDGE_PROTOCOL_VERSION))
    );
}

#[test]
fn next_step_requests_serialize_protocol_version() {
    let value = serde_json::to_value(test_next_step_request()).unwrap();

    assert_eq!(
        value.pointer("/protocolVersion"),
        Some(&json!(LANGGRAPH_BRIDGE_PROTOCOL_VERSION))
    );
}

fn test_next_step_request() -> NextStepBridgeRequest {
    NextStepBridgeRequest {
        protocol_version: LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
        envelope_type: "next-step",
        model: "test-runtime-model".to_string(),
        cwd: ".".to_string(),
        system_prompt: "system".to_string(),
        messages: vec![json!({"role": "user", "content": "prompt"})],
        tools: Vec::new(),
        max_tokens: 128,
        api_key_env: "OPENAI_API_KEY".to_string(),
        api_key: None,
        base_url: None,
        runtime_options: None,
        temperature: None,
    }
}
