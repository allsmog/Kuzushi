use super::*;
use serde_json::json;
use std::cell::Cell;
use std::fmt::Write as _;

fn contract(schema: Value) -> StructuredJsonContract {
    StructuredJsonContract::new("test:tool", "TestSchema", schema)
}

fn response_text(text: String, cost_usd: f64) -> AgentQueryResponse {
    AgentQueryResponse {
        text,
        cost_usd,
        cost_usd_reported: true,
        ..Default::default()
    }
}

#[test]
fn mixed_balanced_candidates_keep_last_first_textual_order() {
    let text = r#"prefix {"first":1} [2] {"last":3}"#;

    let slices = balanced_json_slices(text).unwrap();
    let parsed = parse_json_value_from_agent_text_with_strategy(text).unwrap();

    assert_eq!(slices, vec![r#"{"last":3}"#, "[2]", r#"{"first":1}"#]);
    assert_eq!(parsed.value["last"], 3);
    assert_eq!(parsed.strategy.as_str(), "balanced_object");
}

#[test]
fn incomplete_or_mismatched_outer_never_leaks_a_nested_value() {
    let incomplete = r#"prefix {"broken":[1,{"nested":true} tail"#;
    let mismatched = r#"prefix {] tail"#;
    let incomplete_string = r#"prefix {"broken":"quoted { [ } ]"#;

    assert!(parse_json_value_from_agent_text(incomplete).is_err());
    assert!(parse_json_value_from_agent_text(mismatched).is_err());
    assert!(parse_json_value_from_agent_text(incomplete_string).is_err());
    assert!(balanced_json_slices(incomplete).unwrap().is_empty());
    assert!(balanced_json_slices(mismatched).unwrap().is_empty());
    assert!(balanced_json_slices(incomplete_string).unwrap().is_empty());
}

#[test]
fn balanced_slice_helper_rejects_oversized_text_before_scanning() {
    let text = format!(
        "{}{{\"findings\":[]}}",
        "x".repeat(MAX_STRUCTURED_RESPONSE_BYTES)
    );

    let error = balanced_json_slices(&text).unwrap_err().to_string();

    assert!(error.contains("response text"), "{error}");
    assert!(error.contains(&text.len().to_string()), "{error}");
}

#[test]
fn scanner_work_and_retention_are_explicitly_linear_and_bounded() {
    let text = format!("{}{}", "{} ".repeat(640), "{".repeat(100_000));

    let stats = balanced_json_scan_stats(&text);

    assert_eq!(stats.inspected_bytes, text.len());
    assert_eq!(stats.completed_outer_spans, 640);
    assert_eq!(stats.retained_spans, MAX_BALANCED_CANDIDATES);
    assert!(stats.retained_bytes <= MAX_BALANCED_CANDIDATE_BYTES);
    assert_eq!(stats.max_stack_depth, 100_000);
}

#[test]
fn multi_megabyte_scanner_work_is_one_accounted_pass() {
    let quoted = json!({"text": r#"escaped quote: \" and delimiters { [ ] }"#}).to_string();
    let text = format!(
        "{}{}{}",
        "]}".repeat(300_000),
        quoted,
        "{".repeat(1_500_000)
    );

    let stats = balanced_json_scan_stats(&text);

    assert_eq!(stats.inspected_bytes, text.len());
    assert_eq!(stats.completed_outer_spans, 1);
    assert_eq!(stats.retained_spans, 1);
    assert_eq!(stats.max_stack_depth, 1_500_000);
}

#[test]
fn discarded_mismatched_outer_does_not_hide_a_later_top_level_value() {
    let text = r#"prefix [{] } {"final":true} [1,2,3]"#;

    let slices = balanced_json_slices(text).unwrap();
    let parsed = parse_json_value_from_agent_text(text).unwrap();

    assert_eq!(slices, vec!["[1,2,3]", r#"{"final":true}"#]);
    assert_eq!(parsed, json!([1, 2, 3]));
}

#[test]
fn repair_request_preserves_runtime_options_and_temperature() {
    let runtime_options = crate::runtime::AgentRuntimeOptions {
        mcp_tool_timeout_ms: Some(12_345),
        bridge_verbose: Some(true),
        ..Default::default()
    };
    let request = AgentQueryRequest::new("model", ".", "system", "prompt")
        .with_runtime_options(runtime_options.clone())
        .with_temperature(0.125)
        .with_thinking_level("high")
        .with_max_output_tokens(777);

    let repair = repair_request_from(
        &request,
        "repair".to_string(),
        AgentStructuredOutput::json_schema("Repair", json!({"type": "object"})),
    );

    assert_eq!(repair.runtime_options, Some(runtime_options));
    assert_eq!(repair.temperature, Some(0.125));
    assert_eq!(repair.thinking_level.as_deref(), Some("high"));
    assert_eq!(repair.max_output_tokens, Some(777));
}

#[test]
fn thousands_of_fences_have_linear_accounted_work() {
    let mut text = String::new();
    for index in 0..5_000 {
        writeln!(text, "```json\n{{\"index\":{index}}}\n```").unwrap();
    }

    let stats = fenced_json_scan_stats(&text);
    let parsed = parse_json_value_from_agent_text(&text).unwrap();

    assert_eq!(stats.inspected_bytes, text.len());
    assert_eq!(stats.candidate_count, 5_000);
    assert!(stats.parsed_candidate_bytes <= text.len());
    assert_eq!(parsed["index"], 4_999);
}

#[test]
fn oversized_initial_response_is_observed_and_never_repaired() {
    let text = "x".repeat(MAX_STRUCTURED_RESPONSE_BYTES + 1);
    let digest = kuzushi_mcp_common::cache::sha256_hex_bytes(text.as_bytes());
    let response = response_text(text, 0.25);

    let error = parse_or_repair_required_structured_json_with_cost(
        response,
        contract(Value::Null),
        Ok::<_, anyhow::Error>,
        |_, _| panic!("oversized response must not trigger repair"),
    )
    .unwrap_err();
    let failure = error.downcast_ref::<StructuredOutputError>().unwrap();
    let message = format!("{error:#}");

    assert_eq!(failure.cost_report().exact_usd(), Some(0.25));
    assert!(message.contains(&MAX_STRUCTURED_RESPONSE_BYTES.to_string()));
    assert!(message.contains(&digest));
}

#[test]
fn response_budget_counts_text_and_compact_structured_json_together() {
    let structured = json!({"ok": true});
    let structured_bytes = serde_json::to_vec(&structured).unwrap().len();
    let at_limit = AgentQueryResponse {
        text: "x".repeat(MAX_STRUCTURED_RESPONSE_BYTES - structured_bytes),
        structured: Some(structured.clone()),
        ..Default::default()
    };
    ensure_response_material_budget(&at_limit).unwrap();

    let over_limit = AgentQueryResponse {
        text: format!("{}x", at_limit.text),
        structured: Some(structured),
        ..Default::default()
    };
    let error = ensure_response_material_budget(&over_limit)
        .unwrap_err()
        .to_string();

    assert!(error.contains(&(MAX_STRUCTURED_RESPONSE_BYTES + 1).to_string()));
}

#[test]
fn repair_prompt_bounds_schema_error_and_raw_material() {
    let raw = "not-json ".repeat(10_000);
    let raw_digest = kuzushi_mcp_common::cache::sha256_hex_bytes(raw.as_bytes());
    let schema = json!({"description": "s".repeat(100_000)});
    let schema_bytes = serde_json::to_vec(&schema).unwrap();
    let schema_digest = kuzushi_mcp_common::cache::sha256_hex_bytes(&schema_bytes);

    let result = parse_or_repair_required_structured_json(
        response_text(raw, 0.1),
        contract(schema),
        Ok,
        |prompt, _| {
            assert!(prompt.len() <= MAX_REPAIR_PROMPT_BYTES);
            assert!(prompt.contains(&raw_digest), "{prompt}");
            assert!(prompt.contains(&schema_digest), "{prompt}");
            Ok(AgentQueryResponse {
                structured: Some(json!({"ok": true})),
                ..Default::default()
            })
        },
    )
    .unwrap();

    assert_eq!(result["ok"], true);
}

#[test]
fn repair_prompt_streams_and_bounds_large_validation_errors() {
    let validation_error = "validator-detail-".repeat(20_000);
    let error_digest = kuzushi_mcp_common::cache::sha256_hex_bytes(validation_error.as_bytes());
    let calls = Cell::new(0usize);
    let validate = |value| {
        calls.set(calls.get() + 1);
        (calls.get() > 1)
            .then_some(value)
            .ok_or_else(|| anyhow::anyhow!(validation_error.clone()))
    };

    let result = parse_or_repair_required_structured_json(
        AgentQueryResponse {
            structured: Some(json!({"first": true})),
            ..Default::default()
        },
        contract(Value::Null),
        validate,
        |prompt, _| {
            assert!(prompt.len() <= MAX_REPAIR_PROMPT_BYTES);
            assert!(prompt.contains(&error_digest), "{prompt}");
            Ok(AgentQueryResponse {
                structured: Some(json!({"repaired": true})),
                ..Default::default()
            })
        },
    )
    .unwrap();

    assert_eq!(result["repaired"], true);
}

#[test]
fn final_repair_diagnostic_is_bounded_and_digests_both_responses() {
    let initial = "initial-invalid ".repeat(7_000);
    let repair = "repair-invalid ".repeat(7_000);
    let initial_digest = kuzushi_mcp_common::cache::sha256_hex_bytes(initial.as_bytes());
    let repair_digest = kuzushi_mcp_common::cache::sha256_hex_bytes(repair.as_bytes());

    let error = parse_or_repair_required_structured_json(
        response_text(initial, 0.1),
        contract(Value::Null),
        Ok,
        |_, _| Ok(response_text(repair, 0.2)),
    )
    .unwrap_err();
    let message = format!("{error:#}");

    assert!(message.len() <= MAX_STRUCTURED_DIAGNOSTIC_BYTES);
    assert!(std::str::from_utf8(message.as_bytes()).is_ok());
    assert!(message.contains(&initial_digest), "{message}");
    assert!(message.contains(&repair_digest), "{message}");
    assert!(message.contains("bounded evidence"), "{message}");
}

#[test]
fn truncation_diagnostic_is_bounded_utf8_and_digests_partial_response() {
    let partial = format!(r#"{{"payload":"{}"#, "é".repeat(50_000));
    let digest = kuzushi_mcp_common::cache::sha256_hex_bytes(partial.as_bytes());
    let mut response = response_text(partial, 0.1);
    response.truncated = true;
    response.stop_reason = Some("length".to_string());

    let error =
        parse_or_repair_required_structured_json(response, contract(Value::Null), Ok, |_, _| {
            panic!("truncated response must not repair")
        })
        .unwrap_err();
    let message = format!("{error:#}");

    assert!(message.len() <= MAX_STRUCTURED_DIAGNOSTIC_BYTES);
    assert!(std::str::from_utf8(message.as_bytes()).is_ok());
    assert!(message.contains(&digest), "{message}");
    assert!(message.contains("source was truncated"), "{message}");
}

#[test]
fn oversized_repair_response_keeps_both_observed_costs() {
    let repair = "r".repeat(MAX_STRUCTURED_RESPONSE_BYTES + 1);
    let digest = kuzushi_mcp_common::cache::sha256_hex_bytes(repair.as_bytes());

    let error = parse_or_repair_required_structured_json_with_cost(
        response_text("not json".to_string(), 0.1),
        contract(Value::Null),
        Ok::<_, anyhow::Error>,
        |_, _| Ok(response_text(repair, 0.2)),
    )
    .unwrap_err();
    let failure = error.downcast_ref::<StructuredOutputError>().unwrap();

    assert!((failure.cost_report().observed_usd() - 0.3).abs() < 1e-9);
    assert!(failure.cost_report().is_complete());
    assert!(format!("{error:#}").contains(&digest));
}
