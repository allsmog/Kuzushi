use super::*;

pub(crate) fn resolve_model_selector(selector: &str) -> Option<&'static ModelChoice> {
    let key = selector.trim().to_ascii_lowercase().replace('_', "-");
    match key.as_str() {
        "1" | "gpt-5.5" | "5.5" | "openai:gpt-5.5" => MODEL_CHOICES.get(0),
        "2" | "gpt-5.5-mini" | "5.5-mini" | "mini" | "openai:gpt-5.5-mini" => MODEL_CHOICES.get(1),
        "3"
        | "openai-oauth:gpt-5.5"
        | "oauth:gpt-5.5"
        | "codex:gpt-5.5"
        | "openai-codex:gpt-5.5"
        | "codex-5.5" => MODEL_CHOICES.get(2),
        "4"
        | "openai-oauth:gpt-5.5-mini"
        | "oauth:gpt-5.5-mini"
        | "codex:gpt-5.5-mini"
        | "openai-codex:gpt-5.5-mini"
        | "codex-mini" => MODEL_CHOICES.get(3),
        "5" | "sonnet" | "claude-sonnet" | "claude-sonnet-4-6" | "anthropic:claude-sonnet-4-6" => {
            MODEL_CHOICES.get(4)
        }
        "6" | "opus" | "claude-opus" | "claude-opus-4-7" | "anthropic:claude-opus-4-7" => {
            MODEL_CHOICES.get(5)
        }
        _ => None,
    }
}

pub(crate) fn normalize_thinking_level(value: &str) -> Option<&'static str> {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .replace(['_', '-', ' '], "");
    match normalized.as_str() {
        "low" => Some("low"),
        "medium" | "med" => Some("medium"),
        "high" => Some("high"),
        "xhigh" | "xtrahigh" | "extrahigh" => Some("xhigh"),
        _ => None,
    }
}
