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
