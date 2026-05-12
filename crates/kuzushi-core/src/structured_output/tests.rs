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
}
