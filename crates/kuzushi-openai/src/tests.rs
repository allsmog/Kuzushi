#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::{
        AgentQueryRequest, AgentRuntime, AgentRuntimeOptions, Finding, RuntimeConfig, RuntimeKind,
        Severity, TriageRequest,
    };
    use std::collections::BTreeMap;

    #[test]
    fn uses_configured_bridge_command() {
        let runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            agent_bridge_command: Some(vec!["node".to_string(), "bridge.mjs".to_string()]),
            anthropic_oauth: None,
        };

        let bridge = PiAgentCoreRuntime::from_runtime_config(&runtime, ".").unwrap();
        assert_eq!(
            bridge.command(),
            &["node".to_string(), "bridge.mjs".to_string()]
        );
    }

    #[test]
    fn next_step_bridge_round_trips_tool_call_then_final() {
        use kuzushi_core::{AgentTool, AgentToolLoopRequest, ToolCall, ToolResult};
        // A fake bridge that returns a tool_call on first stdin, then a
        // final on the second. We persist a counter file between calls
        // so a single bridge command can serve both invocations.
        let tmp = tempfile::tempdir().unwrap();
        let counter = tmp.path().join("counter");
        std::fs::write(&counter, "0").unwrap();
        let script = format!(
            r#"#!/bin/sh
N=$(cat {counter})
echo $((N+1)) > {counter}
if [ "$N" = "0" ]; then
  printf '%s' '{{"ok":true,"step":"tool_call","call":{{"name":"read_source","input":{{"file":"a.c"}},"callId":"c1"}},"costUsd":0.01}}'
else
  printf '%s' '{{"ok":true,"step":"final","text":"done","costUsd":0.02}}'
fi
"#,
            counter = counter.display()
        );
        let bridge = tmp.path().join("bridge.sh");
        std::fs::write(&bridge, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bridge, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "ANTHROPIC_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            agent_bridge_command: Some(vec![bridge.to_string_lossy().into_owned()]),
            anthropic_oauth: None,
        };
        let bridge = PiAgentCoreRuntime::from_runtime_config(&runtime, ".").unwrap();
        assert!(bridge.supports_tools());

        let req = AgentToolLoopRequest {
            model: "anthropic:claude-sonnet-4-6".to_string(),
            cwd: ".".into(),
            system_prompt: "sys".to_string(),
            prompt: "scan it".to_string(),
            tools: vec![AgentTool {
                name: "read_source".to_string(),
                description: "read a file".to_string(),
                input_schema: serde_json::json!({"type":"object"}),
            }],
            max_steps: 4,
            runtime_options: None,
        };

        let step1 = bridge.next_step_blocking(&req, &[]).unwrap();
        match step1 {
            kuzushi_core::AgentLoopStep::ToolCall { call } => {
                assert_eq!(call.name, "read_source");
                assert_eq!(call.call_id, "c1");
                assert_eq!(call.input["file"], "a.c");
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }

        let history = vec![
            kuzushi_core::LoopHistoryEntry::AssistantToolCall(ToolCall {
                name: "read_source".to_string(),
                input: serde_json::json!({"file":"a.c"}),
                call_id: "c1".to_string(),
            }),
            kuzushi_core::LoopHistoryEntry::ToolResult(ToolResult {
                call_id: "c1".to_string(),
                output: serde_json::json!({"contents":"void a(){}"}),
                is_error: false,
            }),
        ];
        let step2 = bridge.next_step_blocking(&req, &history).unwrap();
        match step2 {
            kuzushi_core::AgentLoopStep::Final { text, cost_usd, .. } => {
                assert_eq!(text, "done");
                assert!((cost_usd.unwrap() - 0.02).abs() < 1e-9);
            }
            other => panic!("expected Final, got {other:?}"),
        }
    }

    #[test]
    fn next_step_bridge_surfaces_error_payload() {
        use kuzushi_core::{AgentTool, AgentToolLoopRequest};
        let runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "ANTHROPIC_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            agent_bridge_command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s' '{\"ok\":false,\"error\":\"no Anthropic credentials\"}'; exit 1"
                    .to_string(),
            ]),
            anthropic_oauth: None,
        };
        let bridge = PiAgentCoreRuntime::from_runtime_config(&runtime, ".").unwrap();
        let req = AgentToolLoopRequest {
            model: "anthropic:claude-sonnet-4-6".to_string(),
            cwd: ".".into(),
            system_prompt: "sys".to_string(),
            prompt: "p".to_string(),
            tools: vec![AgentTool {
                name: "x".to_string(),
                description: "".to_string(),
                input_schema: serde_json::json!({"type":"object"}),
            }],
            max_steps: 1,
            runtime_options: None,
        };
        let err = bridge
            .next_step_blocking(&req, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("next-step"));
        assert!(err.contains("no Anthropic credentials"));
    }

    #[test]
    fn bridge_failure_json_is_returned_as_actionable_error() {
        let runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            agent_bridge_command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s' '{\"ok\":false,\"error\":\"install @mariozechner/pi-agent-core\"}'; exit 1"
                    .to_string(),
            ]),
            anthropic_oauth: None,
        };
        let bridge = PiAgentCoreRuntime::from_runtime_config(&runtime, ".").unwrap();
        let err = bridge
            .triage_finding_blocking(TriageRequest {
                model: "openai:gpt-4.1".to_string(),
                cwd: ".".into(),
                finding: Finding::new_tool(
                    "semgrep",
                    "demo.sql",
                    "src/db.ts",
                    9,
                    Some(9),
                    Severity::High,
                    "SQL injection in search",
                ),
                prompt_template: None,
            })
            .unwrap_err()
            .to_string();

        assert!(err.contains("pi-agent-core bridge failed"));
        assert!(err.contains("install @mariozechner/pi-agent-core"));
    }

    #[test]
    fn query_forwards_runtime_options_to_bridge_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let payload_path = tmp.path().join("payload.json");
        let script = format!(
            r#"#!/bin/sh
cat > {payload}
printf '%s' '{{"ok":true,"text":"done","costUsd":0.0}}'
"#,
            payload = payload_path.display()
        );
        let bridge_script = tmp.path().join("bridge.sh");
        std::fs::write(&bridge_script, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bridge_script, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: Some("high".to_string()),
            agent_bridge_command: Some(vec![bridge_script.to_string_lossy().into_owned()]),
            anthropic_oauth: None,
        };
        let bridge = PiAgentCoreRuntime::from_runtime_config(&runtime, ".").unwrap();
        let mut mcp_environment = BTreeMap::new();
        mcp_environment.insert(
            "KUZUSHI_JOERN_CPG".to_string(),
            ".kuzushi/cpg.bin".to_string(),
        );

        bridge
            .query_blocking(
                AgentQueryRequest::new("openai:gpt-4.1", ".", "system", "prompt")
                    .with_runtime_options(AgentRuntimeOptions {
                        mcp_environment,
                        mcp_tool_timeout_ms: Some(180_000),
                        bridge_verbose: Some(true),
                        bridge_log_path: Some("bridge.log".to_string()),
                    }),
            )
            .unwrap();

        let payload: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(payload_path).unwrap()).unwrap();
        assert_eq!(payload["thinkingLevel"], serde_json::json!("high"));
        assert_eq!(
            payload["runtimeOptions"]["mcpEnvironment"]["KUZUSHI_JOERN_CPG"],
            serde_json::json!(".kuzushi/cpg.bin")
        );
        assert_eq!(
            payload["runtimeOptions"]["mcpToolTimeoutMs"],
            serde_json::json!(180000)
        );
        assert_eq!(
            payload["runtimeOptions"]["bridgeLogPath"],
            serde_json::json!("bridge.log")
        );
    }
}
