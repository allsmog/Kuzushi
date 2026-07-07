#[cfg(test)]
mod tests {
    use super::super::response::{anthropic_model_for_tier, estimate_cost_usd};
    use super::super::*;
    use kuzushi_core::{
        AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, LoopHistoryEntry,
        ModelTier, TriageOutcome, TriageRequest, TriageVerdict,
    };
    use serde_json::json;

    #[test]
    fn options_from_token_strips_whitespace() {
        let opts = AnthropicOAuthRuntimeOptions::from_token("  sk-ant-oat01-AAA  \n");
        let runtime = AnthropicOAuthRuntime::new(opts).unwrap();
        assert!(runtime.token.starts_with("sk-ant-oat01-"));
        assert!(!runtime.token.ends_with(char::is_whitespace));
    }

    #[test]
    fn options_reject_empty_token() {
        let err = AnthropicOAuthRuntime::new(AnthropicOAuthRuntimeOptions::from_token("   "))
            .unwrap_err();
        assert!(err.to_string().contains("token is empty"));
    }

    #[test]
    fn from_token_file_reads_single_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("tok");
        std::fs::write(&path, "sk-ant-oat01-XYZ\n").unwrap();
        let opts = AnthropicOAuthRuntimeOptions::from_token_file(&path).unwrap();
        assert_eq!(opts.token, "sk-ant-oat01-XYZ");
    }

    #[test]
    fn from_token_file_errors_when_missing() {
        let err = AnthropicOAuthRuntimeOptions::from_token_file("/no/such/path/token").unwrap_err();
        assert!(err.to_string().contains("could not read OAuth token"));
    }

    #[test]
    fn debug_redacts_token() {
        let runtime = AnthropicOAuthRuntime::new(AnthropicOAuthRuntimeOptions::from_token(
            "sk-ant-oat01-SECRET",
        ))
        .unwrap();
        let s = format!("{runtime:?}");
        assert!(!s.contains("SECRET"));
        assert!(s.contains("redacted"));
    }

    #[test]
    fn strip_provider_prefix_removes_provider() {
        assert_eq!(
            strip_provider_prefix("anthropic:claude-opus-4-7"),
            "claude-opus-4-7"
        );
        assert_eq!(strip_provider_prefix("claude-haiku"), "claude-haiku");
        assert_eq!(strip_provider_prefix(""), "");
    }

    #[test]
    fn maybe_parse_json_handles_fenced_response() {
        let v = maybe_parse_json("```json\n{\"k\": 1}\n```").unwrap();
        assert_eq!(v["k"], 1);
    }

    #[test]
    fn maybe_parse_json_handles_unfenced_object() {
        let v = maybe_parse_json("{\"k\": 2}").unwrap();
        assert_eq!(v["k"], 2);
    }

    #[test]
    fn maybe_parse_json_extracts_largest_balanced_block() {
        let v = maybe_parse_json("Here is the result:\n{\"k\": 3}\nThanks").unwrap();
        assert_eq!(v["k"], 3);
    }

    #[test]
    fn maybe_parse_json_returns_none_for_plain_text() {
        assert!(maybe_parse_json("just words").is_none());
    }

    #[test]
    fn anthropic_messages_body_keeps_model_and_user_prompt() {
        let request = AgentQueryRequest::new(
            "anthropic:claude-sonnet-4-6".to_string(),
            ".",
            "system".to_string(),
            "user prompt".to_string(),
        );
        let body = anthropic_messages_body("claude-sonnet-4-6", 2048, &request);
        assert_eq!(body["model"], "claude-sonnet-4-6");
        assert_eq!(body["max_tokens"], 2048);
        assert_eq!(body["system"], "system");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "user prompt");
    }

    #[test]
    fn parse_anthropic_messages_response_concatenates_text_and_usage() {
        let response = parse_anthropic_messages_response(
            "claude-haiku-4-5-20251001",
            r#"{
              "content": [
                {"type":"text","text":"{\"ok\":"},
                {"type":"thinking"},
                {"type":"text","text":"true}"}
              ],
              "usage": {"input_tokens": 1000, "output_tokens": 500}
            }"#,
        )
        .unwrap();

        assert_eq!(response.text, r#"{"ok":true}"#);
        assert_eq!(response.structured.unwrap()["ok"], true);
        assert_eq!(response.input_tokens, 1000);
        assert_eq!(response.output_tokens, 500);
        assert!(response.cost_usd > 0.0);
    }

    #[test]
    fn anthropic_http_status_helper_reports_error_body() {
        ensure_anthropic_success(reqwest::StatusCode::OK, "{}").unwrap();
        let err =
            ensure_anthropic_success(reqwest::StatusCode::UNAUTHORIZED, "bad token").unwrap_err();
        assert!(err.to_string().contains("401 Unauthorized"));
        assert!(err.to_string().contains("bad token"));
    }

    #[test]
    fn build_triage_prompt_includes_template_and_finding() {
        use kuzushi_core::{Finding, Severity};
        let req = TriageRequest {
            model: "anthropic:claude-haiku-4-5-20251001".to_string(),
            cwd: ".".into(),
            finding: Finding::new_tool("test", "rule", "src/x.c", 1, None, Severity::High, "msg"),
            prompt_template: Some("Custom prompt".to_string()),
        };
        let prompt = build_triage_prompt(&req).unwrap();
        assert!(prompt.contains("Custom prompt"));
        assert!(prompt.contains("Finding JSON:"));
        assert!(prompt.contains("rule"));
    }

    #[test]
    fn clamp_outcome_caps_confidence() {
        let mut outcome = TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 1.5,
            rationale: "x".to_string(),
            ..Default::default()
        };
        outcome = clamp_outcome(outcome);
        assert_eq!(outcome.confidence, 1.0);
        outcome.confidence = -0.3;
        outcome = clamp_outcome(outcome);
        assert_eq!(outcome.confidence, 0.0);
    }

    #[test]
    fn triage_outcome_from_response_prefers_structured_then_json_text() {
        let structured = triage_outcome_from_response(AgentQueryResponse {
            structured: Some(json!({
                "verdict": "true_positive",
                "confidence": 1.7,
                "rationale": "structured"
            })),
            cost_usd: 0.12,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(structured.verdict, TriageVerdict::TruePositive);
        assert_eq!(structured.confidence, 1.0);
        assert_eq!(structured.cost_usd, 0.12);

        let from_text = triage_outcome_from_response(AgentQueryResponse {
            text: r#"{"verdict":"false_positive","confidence":0.8,"rationale":"json"}"#.to_string(),
            cost_usd: 0.03,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(from_text.verdict, TriageVerdict::FalsePositive);
        assert_eq!(from_text.cost_usd, 0.03);
    }

    #[test]
    fn triage_outcome_from_response_errors_on_plain_or_empty_content() {
        let plain = triage_outcome_from_response(AgentQueryResponse {
            text: "plain rationale".to_string(),
            cost_usd: 0.04,
            ..Default::default()
        })
        .unwrap_err()
        .to_string();
        assert!(plain.contains("not valid triage JSON"));

        let empty = triage_outcome_from_response(AgentQueryResponse {
            cost_usd: 0.05,
            ..Default::default()
        })
        .unwrap_err()
        .to_string();
        assert!(empty.contains("no triage content"));
    }

    #[test]
    fn triage_outcome_from_response_errors_on_schema_violations() {
        let err = triage_outcome_from_response(AgentQueryResponse {
            structured: Some(json!({
                "verdict": "true_positive",
                "confidence": "high",
                "rationale": "reachable"
            })),
            ..Default::default()
        })
        .unwrap_err()
        .to_string();

        assert!(err.contains("violated schema"));
    }

    // ----- cost estimation -----------------------------------------

    #[test]
    fn cost_estimate_uses_haiku_rates_for_haiku_models() {
        let cost = estimate_cost_usd("claude-haiku-4-5-20251001", 1000, 1000);
        // Haiku: $0.0008/k in + $0.004/k out × 1k each.
        assert!((cost - (0.0008 + 0.004)).abs() < 1e-9);
    }

    #[test]
    fn cost_estimate_uses_sonnet_rates_for_sonnet_models() {
        let cost = estimate_cost_usd("claude-sonnet-4-6", 1000, 1000);
        assert!((cost - (0.003 + 0.015)).abs() < 1e-9);
    }

    #[test]
    fn cost_estimate_uses_opus_rates_for_opus_models() {
        let cost = estimate_cost_usd("claude-opus-4-7", 1000, 1000);
        assert!((cost - (0.015 + 0.075)).abs() < 1e-9);
    }

    #[test]
    fn cost_estimate_falls_back_to_sonnet_rates_for_unknown_models() {
        let unknown = estimate_cost_usd("some-future-model", 1000, 1000);
        let sonnet = estimate_cost_usd("claude-sonnet-4-6", 1000, 1000);
        assert!((unknown - sonnet).abs() < 1e-9);
    }

    #[test]
    fn cost_estimate_zero_when_no_tokens() {
        assert_eq!(estimate_cost_usd("claude-haiku-4-5", 0, 0), 0.0);
    }

    // ----- model_for_tier ------------------------------------------

    #[test]
    fn model_for_tier_preserves_sonnet_when_cheap_requested() {
        let resolved = anthropic_model_for_tier(ModelTier::Cheap, "anthropic:claude-sonnet-4-6");
        assert_eq!(resolved, "anthropic:claude-sonnet-4-6");
    }

    #[test]
    fn model_for_tier_preserves_haiku_when_deep_requested() {
        let resolved =
            anthropic_model_for_tier(ModelTier::Deep, "anthropic:claude-haiku-4-5-20251001");
        assert_eq!(resolved, "anthropic:claude-haiku-4-5-20251001");
    }

    #[test]
    fn model_for_tier_keeps_configured_when_already_correct_tier() {
        let resolved =
            anthropic_model_for_tier(ModelTier::Cheap, "anthropic:claude-haiku-4-5-20251001");
        assert_eq!(resolved, "anthropic:claude-haiku-4-5-20251001");
    }

    #[test]
    fn runtime_model_for_tier_dispatches_through_anthropic_helper() {
        let runtime = AnthropicOAuthRuntime::new(AnthropicOAuthRuntimeOptions::from_token(
            "sk-ant-oat01-XYZ",
        ))
        .unwrap();
        let model = runtime.model_for_tier(ModelTier::Cheap, "anthropic:claude-opus-4-7");
        assert_eq!(model, "anthropic:claude-opus-4-7");
    }

    // ── Native tool loop (parity with the LangGraph bridge `next-step`) ──

    fn sample_tool_loop_request() -> kuzushi_core::AgentToolLoopRequest {
        kuzushi_core::AgentToolLoopRequest {
            model: "anthropic:claude-opus-4-7".to_string(),
            cwd: std::path::PathBuf::from("/work"),
            system_prompt: "You are an auditor.".to_string(),
            prompt: "Audit db.rs".to_string(),
            tools: vec![kuzushi_core::AgentTool {
                name: "read_source".to_string(),
                description: "Read a file".to_string(),
                input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
            }],
            max_steps: 8,
            runtime_options: None,
            temperature: Some(0.0),
        }
    }

    #[test]
    fn tool_loop_body_forwards_tools_system_and_conversation() {
        let request = sample_tool_loop_request();
        let history = vec![
            LoopHistoryEntry::AssistantToolCall(kuzushi_core::ToolCall {
                name: "read_source".to_string(),
                input: json!({"path": "db.rs"}),
                call_id: "call-1".to_string(),
            }),
            LoopHistoryEntry::ToolResult(kuzushi_core::ToolResult {
                call_id: "call-1".to_string(),
                output: json!("fn main() {}"),
                is_error: false,
            }),
        ];
        let body = anthropic_tool_loop_body("claude-opus-4-7", 4096, &request, &history);

        assert_eq!(body["model"], "claude-opus-4-7");
        assert_eq!(body["max_tokens"], 4096);
        assert_eq!(body["system"], "You are an auditor.");
        assert_eq!(body["temperature"], 0.0);
        // tools forwarded verbatim as Anthropic tool definitions.
        assert_eq!(body["tools"][0]["name"], "read_source");
        assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
        // conversation = user prompt, then the rendered history turns.
        let messages = body["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"], "Audit db.rs");
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["content"][0]["type"], "tool_use");
        assert_eq!(messages[1]["content"][0]["id"], "call-1");
        assert_eq!(messages[2]["role"], "user");
        assert_eq!(messages[2]["content"][0]["type"], "tool_result");
        assert_eq!(messages[2]["content"][0]["tool_use_id"], "call-1");
    }

    #[test]
    fn tool_loop_body_omits_temperature_when_unset() {
        let mut request = sample_tool_loop_request();
        request.temperature = None;
        let body = anthropic_tool_loop_body("claude-opus-4-7", 4096, &request, &[]);
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn parse_tool_loop_response_maps_tool_use_to_tool_call() {
        let raw = json!({
            "content": [
                {"type": "text", "text": "let me look"},
                {"type": "tool_use", "id": "toolu_42", "name": "read_source",
                 "input": {"path": "db.rs"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 1000, "output_tokens": 200}
        })
        .to_string();

        match parse_tool_loop_response("claude-opus-4-7", &raw).unwrap() {
            AgentLoopStep::ToolCall { call, cost_usd } => {
                assert_eq!(call.name, "read_source");
                assert_eq!(call.call_id, "toolu_42");
                assert_eq!(call.input, json!({"path": "db.rs"}));
                // opus pricing: 1000/1k*0.015 + 200/1k*0.075 = 0.03
                let cost = cost_usd.expect("cost surfaced on tool-call turns");
                assert!((cost - 0.03).abs() < 1e-9, "cost was {cost}");
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
    }

    #[test]
    fn parse_tool_loop_response_maps_text_to_final_with_embedded_json() {
        let raw = json!({
            "content": [{"type": "text", "text": "Result: {\"ok\": true}"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        })
        .to_string();

        match parse_tool_loop_response("claude-opus-4-7", &raw).unwrap() {
            AgentLoopStep::Final {
                text,
                structured,
                cost_usd,
            } => {
                assert_eq!(text, "Result: {\"ok\": true}");
                assert_eq!(structured, Some(json!({"ok": true})));
                assert!(cost_usd.is_some());
            }
            other => panic!("expected Final, got {other:?}"),
        }
    }

    // ── Structured-output contract parity with the LangGraph bridge ──
    //
    // `append_structured_output_contract` must emit the exact system-prompt
    // suffix the bridge's `appendStructuredOutputContract` (model.mjs) sent, so
    // the native runtime does not silently change what the model is told. The
    // golden is produced by `testdata/regenerate_structured_output_contract.mjs`
    // (a verbatim copy of the JS function).

    #[test]
    fn structured_output_contract_matches_langgraph_bridge_golden() {
        let golden = include_str!("testdata/structured_output_contract.golden")
            .strip_suffix('\n')
            .expect("golden file is POSIX newline-terminated");
        // Key order + integer values chosen so serde_json and JSON.stringify agree.
        let schema = json!({
            "additionalProperties": false,
            "properties": {
                "confidence": {"maximum": 1, "minimum": 0, "type": "number"},
                "rationale": {"type": "string"},
                "verdict": {"enum": ["true_positive", "false_positive", "needs_review"],
                            "type": "string"}
            },
            "required": ["verdict", "confidence", "rationale"],
            "type": "object"
        });
        let contract =
            kuzushi_core::AgentStructuredOutput::json_schema("kuzushi_triage_outcome", schema);
        let rendered = kuzushi_core::append_structured_output_contract(
            "You are a triage agent.",
            Some(&contract),
        );
        assert_eq!(rendered, golden, "native contract drifted from bridge golden");
    }

    #[test]
    fn structured_output_contract_without_schema_returns_prompt_unchanged() {
        // Matches the JS `if (!contract) return String(systemPrompt)` branch.
        let rendered =
            kuzushi_core::append_structured_output_contract("just the prompt", None);
        assert_eq!(rendered, "just the prompt");
    }
}
