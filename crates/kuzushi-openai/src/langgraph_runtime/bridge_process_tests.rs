use super::bridge_payloads::{
    BridgeRequest, BridgeResponse, NextStepBridgeRequest, LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
};
use super::bridge_process::{
    bridge_failure_metadata, bridge_near_executable, bridge_runtime_failure,
    bridge_timeout_from_env_value, configure_bridge_process_group,
    default_langgraph_bridge_command, mcp_binary_env_defaults, public_bridge_error,
    public_bridge_failure_with_detail, read_bounded_pipe, run_next_step_bridge,
    wait_with_output_deadline_limits, write_bridge_diagnostics,
};
use super::runtime_impl::estimated_bridge_cost;
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
fn bridge_verbose_forwards_only_bounded_metadata() {
    let sentinel = "raw-prompt-provider-secret-sentinel";
    let valid = r#"[kuzushi-bridge] {"ts":7,"kind":"query","modelProvider":"openai","thinkingLevel":"high","toolCount":2,"promptLen":19,"messageCount":0,"systemPromptLen":11,"responseLen":5,"stopClass":"complete","responseToolCount":0}"#;
    let invalid = format!(
        "[kuzushi-bridge] {{\"ts\":8,\"kind\":\"{sentinel}\",\"modelProvider\":\"openai\",\"toolCount\":0,\"promptLen\":0,\"messageCount\":0,\"systemPromptLen\":0,\"responseLen\":0,\"responseToolCount\":0}}"
    );
    let oversized = format!("[kuzushi-bridge] {}", "x".repeat(5000));
    let captured = format!("untrusted {sentinel}\n{valid}\n{invalid}\n{oversized}\n");
    let mut forwarded = Vec::new();

    write_bridge_diagnostics(captured.as_bytes(), &mut forwarded);

    let forwarded = String::from_utf8(forwarded).unwrap();
    assert!(forwarded.starts_with("[kuzushi-bridge] {\"ts\":7"));
    assert!(forwarded.contains("\"modelProvider\":\"openai\""));
    assert!(!forwarded.contains(sentinel));
    assert_eq!(forwarded.lines().count(), 1);
}

#[test]
fn bridge_output_overflow_kills_the_registered_process_tree() {
    let mut command = Command::new("node");
    command
        .args([
            "-e",
            "const fs=require('node:fs'); for (;;) { try { fs.writeSync(1, '1234567890') } catch { setInterval(()=>{}, 1000); break } }",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let process_group = configure_bridge_process_group(&mut command).unwrap();
    let child = command.spawn().unwrap();
    let started = Instant::now();

    let error = wait_with_output_deadline_limits(
        child,
        process_group,
        "bridge fixture",
        Some(Duration::from_secs(5)),
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
fn bridge_without_configured_ceiling_waits_for_natural_exit() {
    let mut command = Command::new("node");
    command
        .args(["-e", "process.stdout.write('done')"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let process_group = configure_bridge_process_group(&mut command).unwrap();
    let child = command.spawn().unwrap();

    let output = wait_with_output_deadline_limits(
        child,
        process_group,
        "bridge fixture",
        None,
        None,
        1024,
        1024,
    )
    .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, b"done");
}

#[test]
fn bridge_configured_ceiling_kills_overrunning_process() {
    let mut command = Command::new("node");
    command
        .args(["-e", "setTimeout(() => {}, 30000)"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let process_group = configure_bridge_process_group(&mut command).unwrap();
    let child = command.spawn().unwrap();
    let started = Instant::now();

    let error = wait_with_output_deadline_limits(
        child,
        process_group,
        "bridge fixture",
        Some(Duration::from_millis(200)),
        None,
        1024,
        1024,
    )
    .unwrap_err()
    .to_string();

    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(error.contains("KUZUSHI_BRIDGE_TIMEOUT_MS"), "{error}");
}

#[test]
fn bridge_timeout_defaults_and_invalid_overrides_fail_closed() {
    assert_eq!(
        bridge_timeout_from_env_value(None).unwrap(),
        Duration::from_secs(600)
    );
    assert_eq!(
        bridge_timeout_from_env_value(Some("250")).unwrap(),
        Duration::from_millis(250)
    );
    assert!(bridge_timeout_from_env_value(Some("0")).is_err());
    assert!(bridge_timeout_from_env_value(Some("invalid")).is_err());
}

#[test]
fn known_claude_usage_gets_an_observed_cost_when_provider_omits_cost() {
    let response: BridgeResponse = serde_json::from_value(json!({
        "ok": true,
        "input_tokens": 1_000,
        "output_tokens": 500,
    }))
    .unwrap();

    let estimate = estimated_bridge_cost(&response, "vertex:claude-sonnet-4-6").unwrap();
    assert!((estimate - 0.0105).abs() < 1e-12, "{estimate}");
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
fn legacy_missing_api_key_is_classified_as_authentication() {
    let metadata = bridge_failure_metadata(
        None,
        None,
        Some("Missing credentials. Please pass an apiKey"),
        None,
    );

    assert_eq!(
        metadata.error_class,
        kuzushi_core::RuntimeFailureClass::Authentication
    );
    assert_eq!(metadata.public_message(), "Provider authentication failed.");
    assert!(metadata.detail.is_none());
}

#[test]
fn bridge_stderr_failure_rewrites_internal_provider_tokens() {
    let sentinel = "raw-provider-stderr-sentinel";
    let request = test_next_step_request();
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("cat >/dev/null; printf '%s' '{sentinel}' >&2; exit 1"),
    ];

    let error = run_next_step_bridge(&command, &request, None)
        .unwrap_err()
        .to_string();

    assert!(
        error.contains("stdout/stderr details were suppressed"),
        "{error}"
    );
    assert!(!error.contains(sentinel));
}

#[test]
fn bridge_parse_failure_rewrites_internal_provider_tokens() {
    let request = test_next_step_request();
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        "cat >/dev/null; printf '%s' 'malformed openai-codex response'".to_string(),
    ];

    let error = run_next_step_bridge(&command, &request, None)
        .unwrap_err()
        .to_string();

    assert!(
        error.contains("could not parse next-step bridge JSON response"),
        "{error}"
    );
    assert!(!error.contains("openai-codex"));
}

#[test]
fn public_bridge_error_suppresses_arbitrary_provider_content() {
    let sentinel = "raw-provider-body-and-model-response-sentinel";

    let public = public_bridge_error(sentinel);

    assert_eq!(public, "Bridge operation failed.");
    assert!(!public.contains(sentinel));
}

#[test]
fn structured_bridge_failure_ignores_arbitrary_fallback_content() {
    let sentinel = "raw-provider-body-sentinel";

    let public =
        public_bridge_failure_with_detail(Some("rate_limited"), Some(429), Some(sentinel), None);

    assert_eq!(public, "Provider rate limited the request (HTTP 429).");
    assert!(!public.contains(sentinel));
}

#[test]
fn mcp_timeout_failure_is_safe_and_not_mislabeled_as_provider_timeout() {
    let sentinel = "raw-mcp-timeout-sentinel";

    let public = public_bridge_failure_with_detail(Some("mcp_timeout"), None, Some(sentinel), None);

    assert_eq!(public, "MCP tool request timed out.");
    assert!(!public.contains(sentinel));
}

#[test]
fn structured_bridge_failure_preserves_redacted_typed_metadata() {
    let metadata = bridge_failure_metadata(
        Some("sdk_client_validation"),
        None,
        None,
        Some("temperature incompatible with adaptive thinking; Authorization: Bearer sk-live-secret-sentinel"),
    );

    assert_eq!(
        metadata.error_class,
        kuzushi_core::runtime::RuntimeFailureClass::SdkClientValidation
    );
    assert_eq!(
        metadata.detail.as_deref(),
        Some("temperature is incompatible with adaptive thinking; omit the pinned temperature")
    );
}

#[test]
fn bridge_runtime_error_transports_typed_metadata_through_anyhow() {
    let error = bridge_runtime_failure(
        Some("rate_limited"),
        Some(429),
        None,
        Some("quota window exhausted"),
    );
    let metadata = kuzushi_core::runtime::runtime_failure_metadata(&error).unwrap();

    assert_eq!(
        metadata.error_class,
        kuzushi_core::runtime::RuntimeFailureClass::RateLimited
    );
    assert_eq!(metadata.http_status, Some(429));
    assert_eq!(metadata.detail, None);
    assert_eq!(
        error.to_string(),
        "Provider rate limited the request (HTTP 429)."
    );
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
        oauth_credentials_path: "/operator/oauth.json".to_string(),
        oauth_allow_env_token: false,
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
        oauth_credentials_path: "/operator/oauth.json".to_string(),
        oauth_allow_env_token: false,
        base_url: None,
        runtime_options: None,
        temperature: None,
    }
}
