#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::{
        AgentQueryControl, AgentQueryRequest, AgentRuntime, AgentRuntimeOptions, Finding,
        RuntimeConfig, RuntimeKind, ScanCancellation, Severity, TriageRequest,
    };
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    #[test]
    fn langgraph_triage_cost_distinguishes_unpriced_estimate_from_reported_zero() {
        let structured = || {
            Some(serde_json::json!({
                "verdict": "true_positive",
                "confidence": 0.8,
                "rationale": "reachable"
            }))
        };
        let unpriced = crate::langgraph_runtime::triage_outcome_from_response(
            kuzushi_core::AgentQueryResponse {
                structured: structured(),
                estimated_cost_usd: Some(0.25),
                ..Default::default()
            },
        )
        .unwrap();
        let reported_zero = crate::langgraph_runtime::triage_outcome_from_response(
            kuzushi_core::AgentQueryResponse {
                structured: structured(),
                cost_usd_reported: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(unpriced.cost_usd, 0.0);
        assert!(!unpriced.cost_usd_exact);
        assert_eq!(reported_zero.cost_usd, 0.0);
        assert!(reported_zero.cost_usd_exact);
    }

    #[test]
    fn langgraph_triage_parse_error_does_not_echo_model_response() {
        let sentinel = "raw-model-response-sentinel";
        let error = crate::langgraph_runtime::triage_outcome_from_response(
            kuzushi_core::AgentQueryResponse {
                text: sentinel.to_string(),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("not valid triage JSON"));
        assert!(!error.contains(sentinel));
    }

    #[test]
    fn langgraph_triage_schema_error_does_not_echo_model_value() {
        let sentinel = "raw-model-response-sentinel";
        let error = crate::langgraph_runtime::triage_outcome_from_response(
            kuzushi_core::AgentQueryResponse {
                structured: Some(serde_json::json!({
                    "verdict": sentinel,
                    "confidence": 0.8,
                    "rationale": "reachable"
                })),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("violated schema"));
        assert!(!error.contains(sentinel));
    }

    #[test]
    fn uses_configured_bridge_command() {
        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec!["node".to_string(), "bridge.mjs".to_string()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };

        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();
        assert_eq!(
            bridge.command(),
            &["node".to_string(), "bridge.mjs".to_string()]
        );
    }

    #[test]
    fn anthropic_model_rejects_openai_env_without_explicit_operator_config() {
        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec!["node".to_string(), "bridge.mjs".to_string()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();

        let error = match bridge.credential_for_model("anthropic:claude-sonnet-4-6") {
            Ok(_) => panic!("expected mismatched credential env to fail"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("requires ANTHROPIC_API_KEY"), "{error}");
        assert!(
            error.contains("will not silently switch provider credentials"),
            "{error}"
        );
    }

    #[test]
    fn query_bridge_preserves_snake_case_cost_from_bridge_response() {
        let tmp = tempfile::tempdir().unwrap();
        let bridge = tmp.path().join("bridge.sh");
        std::fs::write(
            &bridge,
            r#"#!/bin/sh
printf '%s' '{"ok":true,"text":"done","structured":{"ok":true},"cost_usd":0.1234,"input_tokens":0,"output_tokens":0}'
"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bridge, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![bridge.to_string_lossy().into_owned()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();

        let observed = bridge
            .query_observed_blocking(AgentQueryRequest::new(
                "openai:gpt-5.5".to_string(),
                ".",
                "sys".to_string(),
                "prompt".to_string(),
            ))
            .unwrap();
        let response = observed.value;

        assert_eq!(response.text, "done");
        assert_eq!(response.structured.unwrap()["ok"], serde_json::json!(true));
        assert!((response.cost_usd - 0.1234).abs() < 1e-9);
        assert_eq!(observed.usage.observed_counts(), (Some(0), Some(0)));
    }

    #[test]
    fn query_bridge_cancellation_kills_running_child() {
        let tmp = tempfile::tempdir().unwrap();
        let started = tmp.path().join("started");
        let bridge = tmp.path().join("bridge.sh");
        std::fs::write(
            &bridge,
            format!(
                r#"#!/bin/sh
printf started > {started}
while :; do :; done
"#,
                started = started.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bridge, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![bridge.to_string_lossy().into_owned()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let cancel = ScanCancellation::default();
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".")
            .unwrap()
            .with_cancellation(cancel.clone());
        let handle = std::thread::spawn(move || {
            bridge
                .query_blocking(AgentQueryRequest::new(
                    "openai:gpt-5.5",
                    ".",
                    "sys",
                    "prompt",
                ))
                .unwrap_err()
                .to_string()
        });

        wait_for_file(&started, Duration::from_secs(2));
        let cancelled_at = Instant::now();
        cancel.cancel();

        let error = handle.join().unwrap();

        assert!(
            cancelled_at.elapsed() < Duration::from_secs(2),
            "cancel should not wait for the bridge timeout"
        );
        assert!(error.contains("cancelled"));
    }

    #[cfg(unix)]
    #[test]
    fn controlled_query_deadline_kills_running_bridge() {
        let tmp = tempfile::tempdir().unwrap();
        let started = tmp.path().join("started");
        let bridge = tmp.path().join("bridge.sh");
        std::fs::write(
            &bridge,
            format!(
                "#!/bin/sh\nprintf started > {}\nwhile :; do :; done\n",
                started.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bridge, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let config = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![bridge.to_string_lossy().into_owned()]),
            worker_watchdog_timeout_ms: Some(100),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let runtime = LangGraphRuntime::from_runtime_config(&config, ".").unwrap();
        let started_at = Instant::now();
        let error = runtime
            .query_blocking_controlled(
                AgentQueryRequest::new("openai:gpt-5.5", ".", "sys", "prompt"),
                AgentQueryControl::new(None, Some(Instant::now() + Duration::from_millis(500))),
            )
            .unwrap_err()
            .to_string();

        assert!(started_at.elapsed() < Duration::from_secs(2));
        assert!(error.contains("deadline"), "{error}");
        assert!(started.exists());
    }

    #[cfg(unix)]
    #[test]
    fn query_bridge_cancellation_kills_bridge_process_group() {
        let tmp = tempfile::tempdir().unwrap();
        let started = tmp.path().join("started");
        let survived = tmp.path().join("survived");
        let bridge = tmp.path().join("bridge.sh");
        std::fs::write(
            &bridge,
            format!(
                r#"#!/bin/sh
(sleep 1; printf survived > {survived}) &
printf started > {started}
while :; do sleep 1; done
"#,
                started = started.display(),
                survived = survived.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bridge, std::fs::Permissions::from_mode(0o755)).unwrap();

        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![bridge.to_string_lossy().into_owned()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let cancel = ScanCancellation::default();
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".")
            .unwrap()
            .with_cancellation(cancel.clone());
        let handle = std::thread::spawn(move || {
            bridge
                .query_blocking(AgentQueryRequest::new(
                    "openai:gpt-5.5",
                    ".",
                    "sys",
                    "prompt",
                ))
                .unwrap_err()
                .to_string()
        });

        wait_for_file(&started, Duration::from_secs(2));
        cancel.cancel();
        let error = handle.join().unwrap();
        std::thread::sleep(Duration::from_millis(1500));

        assert!(error.contains("cancelled"));
        assert!(
            !survived.exists(),
            "bridge grandchild survived cancellation and wrote {}",
            survived.display()
        );
    }

    fn wait_for_file(path: &std::path::Path, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn triage_bridge_sets_cost_on_structured_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let bridge = tmp.path().join("bridge.sh");
        std::fs::write(
            &bridge,
            r#"#!/bin/sh
printf '%s' '{"ok":true,"structured":{"verdict":"true_positive","confidence":0.9,"rationale":"reachable"},"costUsd":0.045}'
"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bridge, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![bridge.to_string_lossy().into_owned()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();

        let outcome = bridge
            .triage_finding_blocking(TriageRequest {
                model: "openai:gpt-5.5".to_string(),
                cwd: ".".into(),
                finding: Finding::new_tool(
                    "semgrep",
                    "demo",
                    "src/db.ts",
                    9,
                    Some(9),
                    Severity::High,
                    "SQL injection in search",
                ),
                prompt_template: None,
            })
            .unwrap();

        assert_eq!(outcome.verdict, kuzushi_core::TriageVerdict::TruePositive);
        assert!((outcome.cost_usd - 0.045).abs() < 1e-9);
    }

    #[test]
    fn triage_bridge_rejects_malformed_text_verdict() {
        let tmp = tempfile::tempdir().unwrap();
        let bridge = tmp.path().join("bridge.sh");
        std::fs::write(
            &bridge,
            r#"#!/bin/sh
printf '%s' '{"ok":true,"text":"needs review because the model did not return JSON","costUsd":0.01}'
"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bridge, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![bridge.to_string_lossy().into_owned()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();

        let err = bridge
            .triage_finding_blocking(TriageRequest {
                model: "openai:gpt-5.5".to_string(),
                cwd: ".".into(),
                finding: Finding::new_tool(
                    "semgrep",
                    "demo",
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

        assert!(err.contains("not valid triage JSON"));
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
            kind: RuntimeKind::LangGraph,
            api_key_env: "ANTHROPIC_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![bridge.to_string_lossy().into_owned()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();
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
            temperature: None,
        };

        let step1 = bridge.next_step_blocking(&req, &[]).unwrap();
        match step1 {
            kuzushi_core::AgentLoopStep::ToolCall { call, .. } => {
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
    fn next_step_bridge_surfaces_classified_error_without_raw_payload() {
        use kuzushi_core::{AgentTool, AgentToolLoopRequest};
        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "ANTHROPIC_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s' '{\"ok\":false,\"error\":\"raw-provider-body-sentinel\",\"errorClass\":\"authentication\",\"status\":401}'; exit 1"
                    .to_string(),
            ]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();
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
            temperature: None,
        };
        let err = bridge
            .next_step_blocking(&req, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("next-step"));
        assert!(err.contains("Provider authentication failed (HTTP 401)"));
        assert!(!err.contains("raw-provider-body-sentinel"));
    }

    #[test]
    fn next_step_bridge_rejects_final_step_without_text() {
        use kuzushi_core::{AgentTool, AgentToolLoopRequest};
        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "ANTHROPIC_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s' '{\"ok\":true,\"step\":\"final\"}'".to_string(),
            ]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();
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
            temperature: None,
        };

        let err = bridge
            .next_step_blocking(&req, &[])
            .unwrap_err()
            .to_string();

        assert!(err.contains("final step missing text"));
    }

    #[test]
    fn tool_loop_preflight_surfaces_classified_rejection_before_first_step() {
        use kuzushi_core::{AgentTool, AgentToolLoopRequest};
        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "REQ=$(cat); case \"$REQ\" in *next-step-preflight*) printf '%s' '{\"ok\":false,\"error\":\"raw-provider-scope-sentinel\",\"errorClass\":\"provider_rejected\",\"status\":403}' ;; *) printf '%s' '{\"ok\":true,\"step\":\"final\",\"text\":\"unexpected\"}' ;; esac"
                    .to_string(),
            ]),
            worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();
        let req = AgentToolLoopRequest {
            model: "openai-codex:gpt-5.5".to_string(),
            cwd: ".".into(),
            system_prompt: "sys".to_string(),
            prompt: "p".to_string(),
            tools: vec![AgentTool {
                name: "read_source".to_string(),
                description: "".to_string(),
                input_schema: serde_json::json!({"type":"object"}),
            }],
            max_steps: 1,
            runtime_options: None,
            temperature: None,
        };

        let err = bridge.preflight_tool_loop_blocking(&req).unwrap_err();

        assert!(err.to_string().contains("next-step preflight"));
        assert!(err
            .to_string()
            .contains("Provider rejected the request (HTTP 403)"));
        assert!(!err.to_string().contains("raw-provider-scope-sentinel"));
    }

    #[test]
    fn bridge_failure_json_suppresses_arbitrary_error_content() {
        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s' '{\"ok\":false,\"error\":\"raw-model-response-sentinel\"}'; exit 1"
                    .to_string(),
            ]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();
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

        assert!(err.contains("LangGraph bridge failed"));
        assert!(err.contains("raw error details were suppressed"));
        assert!(!err.contains("raw-model-response-sentinel"));
    }

    #[test]
    fn bridge_failure_rewrites_internal_openai_oauth_provider() {
        let runtime = RuntimeConfig {
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%s' '{\"ok\":false,\"error\":\"next-step: no OpenAI credentials for openai-codex. Set up kuzushi auth login openai-codex\"}'"
                    .to_string(),
            ]),
            worker_watchdog_timeout_ms: Some(kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();

        let err = bridge
            .query_blocking(AgentQueryRequest::new(
                "openai-codex:gpt-5.5",
                ".",
                "system",
                "prompt",
            ))
            .unwrap_err()
            .to_string();

        assert!(err.contains("OpenAI OAuth"));
        assert!(err.contains("kuzushi auth login openai"));
        assert!(!err.contains("openai-codex"));
    }

    #[test]
    fn query_retries_transient_bridge_failures_with_same_request() {
        let tmp = tempfile::tempdir().unwrap();
        let counter = tmp.path().join("counter");
        let payload = tmp.path().join("payload.json");
        std::fs::write(&counter, "0").unwrap();
        let script = format!(
            r#"#!/bin/sh
N=$(cat {counter})
echo $((N+1)) > {counter}
cat > {payload}
if [ "$N" = "0" ]; then
  printf '%s' '{{"ok":false,"error":"OpenAI OAuth responses error: WebSocket closed 1006"}}'
else
  printf '%s' '{{"ok":true,"text":"done","costUsd":0.0}}'
fi
"#,
            counter = counter.display(),
            payload = payload.display()
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
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: None,
            langgraph_bridge_command: Some(vec![bridge_script.to_string_lossy().into_owned()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();
        let response = bridge
            .query_blocking(AgentQueryRequest::new(
                "openai-codex:gpt-5.5",
                ".",
                "system",
                "prompt",
            ))
            .unwrap();

        assert_eq!(response.text, "done");
        assert_eq!(std::fs::read_to_string(counter).unwrap().trim(), "2");
        let retried_payload = std::fs::read_to_string(payload).unwrap();
        assert!(retried_payload.contains("\"model\":\"openai-codex:gpt-5.5\""));
        assert!(retried_payload.contains("\"prompt\":\"prompt\""));
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
            kind: RuntimeKind::LangGraph,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            thinking_level: Some("high".to_string()),
            langgraph_bridge_command: Some(vec![bridge_script.to_string_lossy().into_owned()]),
            worker_watchdog_timeout_ms: Some(
                kuzushi_core::config::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS,
            ),
            bridge_retry_attempts: None,
            bridge_retry_backoff_ms: None,
            anthropic_oauth: None,
        };
        let bridge = LangGraphRuntime::from_runtime_config(&runtime, ".").unwrap();
        let mut mcp_environment = BTreeMap::new();
        mcp_environment.insert(
            "KUZUSHI_CODEQL_CACHE_DIR".to_string(),
            ".kuzushi/codeql-cache".to_string(),
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
            payload["runtimeOptions"]["mcpEnvironment"]["KUZUSHI_CODEQL_CACHE_DIR"],
            serde_json::json!(".kuzushi/codeql-cache")
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
