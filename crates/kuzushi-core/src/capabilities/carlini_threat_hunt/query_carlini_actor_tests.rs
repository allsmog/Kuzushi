use super::*;

#[test]
fn carlini_thinking_level_inherits_and_honors_override_keys() {
    let reasoning = |value| limits::actor_reasoning(&value).unwrap();
    assert_eq!(reasoning(json!({})), None);
    assert_eq!(
        reasoning(json!({"thinkingLevel": "medium"})),
        Some("medium".into())
    );
    assert_eq!(
        reasoning(json!({"reasoningEffort": "low"})),
        Some("low".into())
    );
    assert_eq!(reasoning(json!({"effort": "xhigh"})), Some("xhigh".into()));
    assert_eq!(reasoning(json!({"thinkingLevel": ""})), None);
    assert_eq!(
        reasoning(json!({"thinkingLevel": "  high  "})),
        Some("high".into())
    );
}

#[test]
fn carlini_max_output_tokens_accepts_operator_cap_aliases() {
    let cap = |value| {
        limits::bounded_integer(
            &value,
            &["maxOutputTokens", "max_output_tokens", "maxTokens"],
            4096,
            256..=32768,
        )
    };
    assert_eq!(cap(json!({})).unwrap(), 4096);
    assert_eq!(cap(json!({"maxOutputTokens":32000})).unwrap(), 32000);
    assert_eq!(cap(json!({"max_output_tokens":16000})).unwrap(), 16000);
    assert_eq!(cap(json!({"maxTokens":8000})).unwrap(), 8000);
    assert!(cap(json!({"maxOutputTokens":0})).is_err());
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
fn carlini_refuses_oversized_text_before_direct_extraction() {
    let response = AgentQueryResponse {
        text: format!(
            "{}{{\"findings\":[]}}",
            "x".repeat(crate::structured_output::MAX_STRUCTURED_RESPONSE_BYTES)
        ),
        ..AgentQueryResponse::default()
    };

    assert!(extract_carlini_findings_response(&response).is_none());

    let artifact =
        carlini_actor_response_artifact_payload("carlini-threat-hunt:User:0", "initial", &response);
    assert_eq!(artifact["ignoredToolPrelude"]["present"], json!(false));
    assert!(artifact["ignoredToolPrelude"]["reason"]
        .as_str()
        .unwrap()
        .contains("exceeded"));
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
