use anyhow::{Context, Result};
use kuzushi_core::ModelTier;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
        .map(|usage| {
            (
                usage.input_tokens.unwrap_or(0),
                usage.output_tokens.unwrap_or(0),
            )
        })
        .unwrap_or((0, 0))
}

pub(crate) fn estimate_cost_usd(model: &str, input_tokens: u32, output_tokens: u32) -> Option<f64> {
    let model = model.to_ascii_lowercase();
    let (in_per_1k, out_per_1k) = token_prices_per_1k(&model)?;
    Some((input_tokens as f64) / 1000.0 * in_per_1k + (output_tokens as f64) / 1000.0 * out_per_1k)
}

fn token_prices_per_1k(model: &str) -> Option<(f64, f64)> {
    if model.contains("opus") {
        Some((15.0e-3, 75.0e-3))
    } else if model.contains("sonnet") {
        Some((3.0e-3, 15.0e-3))
    } else if model.contains("haiku") {
        Some((0.8e-3, 4.0e-3))
    } else {
        None
    }
}

pub(crate) fn anthropic_model_for_tier(tier: ModelTier, configured: &str) -> String {
    let _ = tier;
    configured.to_string()
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
    let fence_stripped = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|s| s.rsplit_once("```").map(|(body, _)| body.trim()))
        .unwrap_or(trimmed);
    if let Ok(value) = serde_json::from_str::<Value>(fence_stripped) {
        return Some(value);
    }
    let (Some(start), Some(end)) = (fence_stripped.find('{'), fence_stripped.rfind('}')) else {
        return None;
    };
    if end > start {
        serde_json::from_str::<Value>(&fence_stripped[start..=end]).ok()
    } else {
        None
    }
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
    pub(crate) input_tokens: Option<u32>,
    #[serde(default)]
    pub(crate) output_tokens: Option<u32>,
}
