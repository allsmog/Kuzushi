use super::prelude::*;
use super::*;

pub(crate) fn anthropic_response_text(parsed: &ApiResponse) -> String {
    parsed
        .content
        .iter()
        .filter_map(|block| match block {
            ApiContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

pub(crate) fn anthropic_response_usage(parsed: &ApiResponse) -> (u32, u32) {
    parsed
        .usage
        .as_ref()
        .map(|usage| (usage.input_tokens, usage.output_tokens))
        .unwrap_or((0, 0))
}

pub(crate) fn estimate_cost_usd(model: &str, input_tokens: u32, output_tokens: u32) -> f64 {
    // (input_per_1k, output_per_1k) — Mar 2026 list prices.
    let m = model.to_ascii_lowercase();
    let (in_per_1k, out_per_1k) = if m.contains("opus") {
        (15.0e-3, 75.0e-3)
    } else if m.contains("sonnet") {
        (3.0e-3, 15.0e-3)
    } else if m.contains("haiku") {
        (0.8e-3, 4.0e-3)
    } else {
        // Unknown model: use Sonnet rates as a conservative default
        // (errs on the side of overcounting cost).
        (3.0e-3, 15.0e-3)
    };
    (input_tokens as f64) / 1000.0 * in_per_1k + (output_tokens as f64) / 1000.0 * out_per_1k
}

pub(crate) fn anthropic_model_for_tier(tier: ModelTier, configured: &str) -> String {
    let configured_clean = strip_provider_prefix(configured);
    let already_haiku = configured_clean.contains("haiku");
    let already_sonnet = configured_clean.contains("sonnet");
    let already_opus = configured_clean.contains("opus");
    match tier {
        ModelTier::Cheap if !already_haiku => "claude-haiku-4-5-20251001".to_string(),
        ModelTier::Mid if !already_sonnet => "claude-sonnet-4-6".to_string(),
        ModelTier::Deep if !already_opus => "claude-opus-4-7".to_string(),
        // Configured model already matches the requested tier — keep it.
        _ => configured_clean,
    }
}

pub(crate) fn strip_provider_prefix(model: &str) -> String {
    match model.split_once(':') {
        Some((_, rest)) if !rest.is_empty() => rest.to_string(),
        _ => model.to_string(),
    }
}

pub(crate) fn dirs_home() -> Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .context("could not resolve home directory (HOME / USERPROFILE)")
}

pub(crate) fn maybe_parse_json(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    // Strip ```json fences if present.
    let fence_stripped = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|s| s.rsplit_once("```").map(|(body, _)| body.trim()))
        .unwrap_or(trimmed);
    if let Ok(v) = serde_json::from_str::<Value>(fence_stripped) {
        return Some(v);
    }
    // Last-ditch: extract the largest balanced {...} from the text.
    if let (Some(start), Some(end)) = (fence_stripped.find('{'), fence_stripped.rfind('}')) {
        if end > start {
            if let Ok(v) = serde_json::from_str::<Value>(&fence_stripped[start..=end]) {
                return Some(v);
            }
        }
    }
    None
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ApiResponse {
    #[serde(default)]
    pub(crate) content: Vec<ApiContentBlock>,
    #[serde(default)]
    pub(crate) usage: Option<ApiUsage>,
    #[serde(default)]
    pub(crate) stop_reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ApiContentBlock {
    Text {
        text: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub(crate) struct ApiUsage {
    #[serde(default)]
    pub(crate) input_tokens: u32,
    #[serde(default)]
    pub(crate) output_tokens: u32,
}
