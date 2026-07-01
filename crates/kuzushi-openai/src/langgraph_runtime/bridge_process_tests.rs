use super::bridge_payloads::NextStepBridgeRequest;
use super::bridge_process::{
    bridge_near_executable, default_langgraph_bridge_command, mcp_binary_env_defaults,
    public_bridge_error, run_next_step_bridge,
};
use serde_json::json;
use std::fs;
use tempfile::tempdir;

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
    let request = test_next_step_request();
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        "printf '%s' 'no credentials for openai-codex; run auth login openai-codex' >&2; exit 1"
            .to_string(),
    ];

    let error = run_next_step_bridge(&command, &request, None)
        .unwrap_err()
        .to_string();

    assert!(error.contains("OpenAI OAuth"));
    assert!(error.contains("auth login openai"));
    assert!(!error.contains("openai-codex"));
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

    assert!(error.contains("OpenAI OAuth"));
    assert!(!error.contains("openai-codex"));
}

fn test_next_step_request() -> NextStepBridgeRequest {
    NextStepBridgeRequest {
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
