#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn extracts_first_parseable_balanced_json_without_using_last_brace_in_prose() {
        let parsed =
            parse_json_value_from_agent_text("before {not json} then {\"ok\":true} after }")
                .unwrap();
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn parses_json_fence() {
        let parsed = parse_json_value_from_agent_text("```json\n{\"ok\":true}\n```").unwrap();
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn truncated_response_short_circuits_to_actionable_error() {
        let response = AgentQueryResponse {
            text: "{\"findings\":[{\"id\":\"F1\",\"description\":\"unter".to_string(),
            truncated: true,
            stop_reason: Some("length".to_string()),
            ..Default::default()
        };
        let contract = StructuredJsonContract::new("test:tool", "TestSchema", Value::Null);
        let result: Result<Value> =
            parse_or_repair_required_structured_json(response, contract, Ok, |_, _| {
                panic!("repair should not run for truncated responses")
            });

        let message = format!("{:#}", result.expect_err("truncation must error"));
        assert!(message.contains("truncated"), "{message}");
        assert!(message.contains("maxOutputTokens"), "{message}");
        assert!(message.contains("test:tool"), "{message}");
    }

    #[test]
    fn a_turn_limit_truncation_recommends_the_turn_budget_not_output_tokens() {
        let response = AgentQueryResponse {
            text: "Let me read one more file".to_string(),
            truncated: true,
            stop_reason: Some("model_turn_limit".to_string()),
            ..Default::default()
        };
        let contract = StructuredJsonContract::new("agentic-sast:scan", "Findings", Value::Null);
        let result: Result<Value> =
            parse_or_repair_required_structured_json(response, contract, Ok, |_, _| {
                panic!("truncation never repairs")
            });

        let message = format!("{:#}", result.unwrap_err());
        assert!(message.contains("maxModelTurns"), "{message}");
        assert!(!message.contains("maxOutputTokens"), "{message}");
    }

    #[test]
    fn valid_structured_json_is_refused_when_completion_was_forced() {
        let response = AgentQueryResponse {
            text: "{\"verdict\":\"confirmed\"}".to_string(),
            structured: Some(serde_json::json!({"verdict": "confirmed"})),
            truncated: true,
            stop_reason: Some("forced_conclusion".to_string()),
            ..Default::default()
        };
        let contract = StructuredJsonContract::new("verify:finding", "Verdict", Value::Null);

        let result: Result<Value> =
            parse_or_repair_required_structured_json(response, contract, Ok, |_, _| {
                panic!("forced conclusions must not reach repair")
            });

        let message = format!("{:#}", result.expect_err("forced conclusion must error"));
        assert!(message.contains("forced_conclusion"), "{message}");
        assert!(message.contains("truncated"), "{message}");
    }

    #[test]
    fn query_required_structured_json_does_not_retry_full_prompt_on_truncation() {
        use crate::findings::TriageOutcome;
        use crate::runtime::TriageRequest;
        use std::sync::Mutex;

        struct TruncatedRuntime {
            calls: Mutex<usize>,
        }

        impl AgentRuntime for TruncatedRuntime {
            fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
                *self.calls.lock().unwrap() += 1;
                Ok(AgentQueryResponse {
                    text: "{\"items\":[".to_string(),
                    truncated: true,
                    stop_reason: Some("length".to_string()),
                    ..Default::default()
                })
            }

            fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
                anyhow::bail!("not used by structured output tests")
            }
        }

        let runtime = TruncatedRuntime {
            calls: Mutex::new(0),
        };
        let contract = StructuredJsonContract::new("test:tool", "TestSchema", Value::Null);
        let request = AgentQueryRequest::new("model", ".", "system", "prompt");

        let result: Result<Value> =
            query_required_structured_json(&runtime, request, contract, Ok::<_, anyhow::Error>);

        assert!(result.is_err());
        assert_eq!(*runtime.calls.lock().unwrap(), 1);
    }

    #[test]
    fn repair_success_reports_checked_initial_plus_repair_cost() {
        let response = AgentQueryResponse {
            text: "not json".to_string(),
            cost_usd: 0.11,
            cost_usd_reported: true,
            ..Default::default()
        };
        let contract = StructuredJsonContract::new("test:tool", "TestSchema", Value::Null);

        let result = parse_or_repair_required_structured_json_with_cost(
            response,
            contract,
            Ok::<_, anyhow::Error>,
            |_, _| {
                Ok(AgentQueryResponse {
                    structured: Some(serde_json::json!({"ok": true})),
                    cost_usd: 0.22,
                    cost_usd_reported: true,
                    ..Default::default()
                })
            },
        )
        .unwrap();

        assert_eq!(result.value["ok"], true);
        assert!((result.cost_usd - 0.33).abs() < 1e-9);
    }

    #[test]
    fn explicit_zero_cost_stays_distinct_from_unreported_cost() {
        let contract = || StructuredJsonContract::new("test:tool", "TestSchema", Value::Null);
        let reported_zero = parse_or_repair_required_structured_json_with_cost(
            AgentQueryResponse {
                structured: Some(serde_json::json!({"ok": true})),
                cost_usd_reported: true,
                ..Default::default()
            },
            contract(),
            Ok::<_, anyhow::Error>,
            |_, _| panic!("valid JSON must not repair"),
        )
        .unwrap();
        let unreported = parse_or_repair_required_structured_json_with_cost(
            AgentQueryResponse {
                structured: Some(serde_json::json!({"ok": true})),
                ..Default::default()
            },
            contract(),
            Ok::<_, anyhow::Error>,
            |_, _| panic!("valid JSON must not repair"),
        )
        .unwrap();

        assert_eq!(reported_zero.cost_report().unwrap().exact_usd(), Some(0.0));
        assert_eq!(unreported.cost_usd, 0.0);
        assert_eq!(unreported.cost_report().unwrap().exact_usd(), None);
        assert!(!unreported.cost_report().unwrap().is_unavailable());
    }

    #[test]
    fn parse_failure_preserves_observed_repair_spend() {
        let response = AgentQueryResponse {
            text: "not json".to_string(),
            cost_usd: 0.11,
            cost_usd_reported: true,
            ..Default::default()
        };
        let contract = StructuredJsonContract::new("test:tool", "TestSchema", Value::Null);

        let error = parse_or_repair_required_structured_json_with_cost(
            response,
            contract,
            Ok::<_, anyhow::Error>,
            |_, _| {
                Ok(AgentQueryResponse {
                    text: "still not json".to_string(),
                    cost_usd: 0.22,
                    cost_usd_reported: true,
                    ..Default::default()
                })
            },
        )
        .unwrap_err();
        let failure = error.downcast_ref::<StructuredOutputError>().unwrap();

        assert!((failure.cost_report().observed_usd() - 0.33).abs() < 1e-9);
        assert!(failure.cost_report().is_complete());
    }

    #[test]
    fn structured_output_error_renders_its_message_exactly_once() {
        // The wrapper contributes one stable context while source() retains
        // the real typed error chain. Rendering the source in both places made
        // anyhow concatenate the provider-safe message with itself.
        let source = anyhow::anyhow!(
            "LangGraph bridge failed: Provider rate limited the request (HTTP 429)."
        );
        let error = anyhow::Error::from(StructuredOutputError::from_source_and_cost(
            source,
            crate::runtime::RuntimeCostReport::UNAVAILABLE,
        ));

        let rendered = format!("{error:#}");

        assert_eq!(rendered.matches("rate limited").count(), 1, "{rendered}");
    }

    #[test]
    fn repair_transport_failure_marks_spend_unresolved_and_keeps_initial_cost() {
        let response = AgentQueryResponse {
            text: "not json".to_string(),
            cost_usd: 0.11,
            cost_usd_reported: true,
            ..Default::default()
        };
        let contract = StructuredJsonContract::new("test:tool", "TestSchema", Value::Null);

        let error = parse_or_repair_required_structured_json_with_cost(
            response,
            contract,
            Ok::<_, anyhow::Error>,
            |_, _| anyhow::bail!("transport disconnected"),
        )
        .unwrap_err();
        let failure = error.downcast_ref::<StructuredOutputError>().unwrap();

        assert_eq!(failure.cost_report().observed_usd(), 0.11);
        assert!(!failure.cost_report().is_complete());
    }

    #[test]
    fn extracts_last_fenced_json_block_when_preceded_by_prose_with_braces() {
        // Regression for the deep-audit "verdict at the bottom of a long
        // rationale paragraph" pattern: prose contains C code with `{`,
        // then the verdict is in a final ```json…``` block. The
        // outermost-`{` scan would pick a brace from the C code; the
        // last-fenced-block path takes the verdict.
        let body = r#"
            Looking at smb2_write at line 7195, the lower bound check
            confirms `DataOffset >= offsetof(struct smb2_write_req, Buffer)`.
            For example:
                if (le16_to_cpu(req->DataOffset) <
                    offsetof(struct smb2_write_req, Buffer)) {
                    err = -EINVAL;
                    goto out;
                }
            That covers the under-bound case.

            ```json
            {
              "triggerable": false,
              "confidence": 0.82,
              "rationale": "validator one frame up enforces upper bound"
            }
            ```
        "#;
        let parsed = parse_json_value_from_agent_text(body).unwrap();
        assert_eq!(parsed["triggerable"], false);
        assert!((parsed["confidence"].as_f64().unwrap() - 0.82).abs() < 1e-6);
        assert!(parsed["rationale"].as_str().unwrap().contains("validator"));
    }

    #[test]
    fn reports_extraction_strategy_for_audits() {
        let parsed = parse_json_value_from_agent_text_with_strategy(
            "analysis {not json}\n```json\n{\"verdict\":\"ok\"}\n```",
        )
        .unwrap();

        assert_eq!(parsed.value["verdict"], "ok");
        assert_eq!(parsed.strategy.as_str(), "last_fenced_block");
    }

    #[test]
    fn malformed_json_like_text_errors_instead_of_fabricating_a_value() {
        let err = parse_json_value_from_agent_text("{\"verdict\": true trailing")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("did not contain a JSON object or array")
                || err.contains("JSON-looking text"),
            "{err}"
        );
        assert!(err.contains("strategies attempted"), "{err}");
    }

    #[test]
    fn typed_helper_round_trips_simple_struct() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Verdict {
            triggerable: bool,
            confidence: f32,
        }
        let body = "Here's the answer:\n```json\n{\"triggerable\":true,\"confidence\":0.91}\n```";
        let v: Verdict = try_parse_typed_from_agent_text(body).unwrap();
        assert_eq!(
            v,
            Verdict {
                triggerable: true,
                confidence: 0.91
            }
        );
    }

    #[test]
    fn typed_helper_rejects_balanced_object_extraction() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Verdict {
            triggerable: bool,
            confidence: f32,
        }
        let body = "Reasoning scratchpad: {\"triggerable\":true,\"confidence\":0.91}. Final: needs review.";

        let parsed: Option<Verdict> = try_parse_typed_from_agent_text(body);

        assert!(parsed.is_none());
    }
}
