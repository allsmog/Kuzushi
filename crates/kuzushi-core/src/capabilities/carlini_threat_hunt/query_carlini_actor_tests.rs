use super::*;

#[test]
fn carlini_thinking_level_defaults_to_high_and_honors_override_keys() {
    assert_eq!(agentic_hunter_thinking_level(&json!({})), "high");
    assert_eq!(
        agentic_hunter_thinking_level(&json!({"thinkingLevel": "medium"})),
        "medium"
    );
    assert_eq!(
        agentic_hunter_thinking_level(&json!({"reasoningEffort": "low"})),
        "low"
    );
    assert_eq!(
        agentic_hunter_thinking_level(&json!({"effort": "xhigh"})),
        "xhigh"
    );
    assert_eq!(
        agentic_hunter_thinking_level(&json!({"thinkingLevel": ""})),
        "high"
    );
    assert_eq!(
        agentic_hunter_thinking_level(&json!({"thinkingLevel": "  high  "})),
        "high"
    );
}

#[test]
fn carlini_max_output_tokens_accepts_operator_cap_aliases() {
    assert_eq!(max_output_tokens_from_input(&json!({})), None);
    assert_eq!(
        max_output_tokens_from_input(&json!({"maxOutputTokens": 32000})),
        Some(32000)
    );
    assert_eq!(
        max_output_tokens_from_input(&json!({"max_output_tokens": 16000})),
        Some(16000)
    );
    assert_eq!(
        max_output_tokens_from_input(&json!({"maxTokens": 8000})),
        Some(8000)
    );
    assert_eq!(
        max_output_tokens_from_input(&json!({"maxOutputTokens": 0})),
        None
    );
}

#[test]
fn carlini_extracts_findings_from_concatenated_tool_transcript() {
    let response = AgentQueryResponse {
        text: r#"{"cmd":"pwd"}{"cmd":"grep -R fopen ."}{"findings":[{"ruleId":"carlini-threat-hunt/example","filePath":"docs/examples/ftp-wildcard.c","startLine":68}]}"#
            .to_string(),
        ..AgentQueryResponse::default()
    };

    let value = extract_carlini_findings_response(&response).expect("findings response");

    assert_eq!(
        value["findings"][0]["ruleId"],
        "carlini-threat-hunt/example"
    );
}

#[test]
fn carlini_response_artifact_marks_tool_shaped_preludes_as_ignored() {
    let response = AgentQueryResponse {
        text: r#"{"cmd":["bash","-lc","grep -R token ."]}{"findings":[]}"#.to_string(),
        ..AgentQueryResponse::default()
    };

    let artifact =
        carlini_actor_response_artifact_payload("carlini-threat-hunt:User:0", "initial", &response);

    assert_eq!(artifact["ignoredToolPrelude"]["present"], json!(true));
    assert_eq!(artifact["ignoredToolPrelude"]["count"], json!(1));
    assert!(artifact["ignoredToolPrelude"]["reason"]
        .as_str()
        .unwrap()
        .contains("was not executed"));
    assert_eq!(
        artifact["ignoredToolPrelude"]["objects"][0]["cmd"][0],
        json!("bash")
    );
}
