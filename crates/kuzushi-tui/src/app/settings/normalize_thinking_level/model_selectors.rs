use super::*;

pub(crate) fn resolve_model_selector(selector: &str) -> Option<&'static ModelChoice> {
    let key = selector.trim().to_ascii_lowercase().replace('_', "-");
    let numeric = key.parse::<usize>().ok();
    MODEL_CHOICES.iter().find(|choice| {
        Some(choice.index) == numeric || choice.id == key || choice.aliases.contains(&key.as_str())
    })
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
