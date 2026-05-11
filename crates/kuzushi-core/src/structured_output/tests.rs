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
}
