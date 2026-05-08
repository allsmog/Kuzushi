#[cfg(test)]
mod tests {
    use super::super::response::{anthropic_model_for_tier, estimate_cost_usd};
    use super::super::*;
    use kuzushi_core::{
        AgentQueryRequest, AgentQueryResponse, AgentRuntime, ModelTier, TriageOutcome,
        TriageRequest, TriageVerdict,
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
    fn triage_outcome_from_response_prefers_structured_then_json_text_then_fallbacks() {
        let structured = triage_outcome_from_response(AgentQueryResponse {
            structured: Some(json!({
                "verdict": "true_positive",
                "confidence": 1.7,
                "rationale": "structured"
            })),
            cost_usd: 0.12,
            ..Default::default()
        });
        assert_eq!(structured.verdict, TriageVerdict::TruePositive);
        assert_eq!(structured.confidence, 1.0);
        assert_eq!(structured.cost_usd, 0.12);

        let from_text = triage_outcome_from_response(AgentQueryResponse {
            text: r#"{"verdict":"false_positive","confidence":0.8,"rationale":"json"}"#.to_string(),
            cost_usd: 0.03,
            ..Default::default()
        });
        assert_eq!(from_text.verdict, TriageVerdict::FalsePositive);
        assert_eq!(from_text.cost_usd, 0.03);

        let plain = triage_outcome_from_response(AgentQueryResponse {
            text: "plain rationale".to_string(),
            cost_usd: 0.04,
            ..Default::default()
        });
        assert_eq!(plain.verdict, TriageVerdict::NeedsReview);
        assert_eq!(plain.confidence, 0.25);
        assert_eq!(plain.rationale, "plain rationale");

        let empty = triage_outcome_from_response(AgentQueryResponse {
            cost_usd: 0.05,
            ..Default::default()
        });
        assert_eq!(empty.verdict, TriageVerdict::NeedsReview);
        assert_eq!(empty.confidence, 0.0);
        assert!(empty.rationale.contains("no triage content"));
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
    fn model_for_tier_promotes_haiku_when_cheap_requested_with_sonnet() {
        let resolved = anthropic_model_for_tier(ModelTier::Cheap, "anthropic:claude-sonnet-4-6");
        assert!(resolved.contains("haiku"));
    }

    #[test]
    fn model_for_tier_promotes_opus_when_deep_requested_with_haiku() {
        let resolved =
            anthropic_model_for_tier(ModelTier::Deep, "anthropic:claude-haiku-4-5-20251001");
        assert!(resolved.contains("opus"));
    }

    #[test]
    fn model_for_tier_keeps_configured_when_already_correct_tier() {
        let resolved =
            anthropic_model_for_tier(ModelTier::Cheap, "anthropic:claude-haiku-4-5-20251001");
        assert_eq!(resolved, "claude-haiku-4-5-20251001");
    }

    #[test]
    fn runtime_model_for_tier_dispatches_through_anthropic_helper() {
        let runtime = AnthropicOAuthRuntime::new(AnthropicOAuthRuntimeOptions::from_token(
            "sk-ant-oat01-XYZ",
        ))
        .unwrap();
        // Ask for Cheap on an Opus-configured model — should down-shift.
        let model = runtime.model_for_tier(ModelTier::Cheap, "anthropic:claude-opus-4-7");
        assert!(model.contains("haiku"));
    }
}
