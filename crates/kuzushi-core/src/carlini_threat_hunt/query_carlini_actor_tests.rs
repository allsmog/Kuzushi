use super::*;

#[test]
fn carlini_thinking_level_defaults_to_high_and_honors_override_keys() {
    assert_eq!(carlini_thinking_level(&json!({})), "high");
    assert_eq!(
        carlini_thinking_level(&json!({"thinkingLevel": "medium"})),
        "medium"
    );
    assert_eq!(
        carlini_thinking_level(&json!({"reasoningEffort": "low"})),
        "low"
    );
    assert_eq!(carlini_thinking_level(&json!({"effort": "xhigh"})), "xhigh");
    assert_eq!(
        carlini_thinking_level(&json!({"thinkingLevel": ""})),
        "high"
    );
    assert_eq!(
        carlini_thinking_level(&json!({"thinkingLevel": "  high  "})),
        "high"
    );
}
