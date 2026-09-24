use anyhow::{Context, Result};
use kuzushi_core::runtime::PromptCacheUsage;
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

pub(crate) fn anthropic_response_prompt_cache(parsed: &ApiResponse) -> Option<PromptCacheUsage> {
    let usage = parsed.usage.as_ref()?;
    if usage.cache_read_input_tokens.is_none() && usage.cache_creation_input_tokens.is_none() {
        return None;
    }
    Some(PromptCacheUsage {
        read_input_tokens: usage.cache_read_input_tokens.unwrap_or(0),
        creation_input_tokens: usage.cache_creation_input_tokens.unwrap_or(0),
    })
}

#[cfg(test)]
pub(crate) fn estimate_cost_usd(model: &str, input_tokens: u32, output_tokens: u32) -> Option<f64> {
    estimate_cost_usd_with_cache(model, input_tokens, output_tokens, None)
}

/// Cache writes (5-minute TTL) bill at 1.25x the input rate. `input_tokens`
/// excludes cached tokens, so the three input buckets add rather than overlap.
const CACHE_CREATION_INPUT_RATE: f64 = 1.25;

/// Anthropic first-party list prices in USD per million tokens.
struct ModelRates {
    input: f64,
    output: f64,
    cache_read: f64,
}

const fn rates(input: f64, output: f64) -> ModelRates {
    // Cache reads bill at a tenth of the input rate unless a model says otherwise.
    ModelRates {
        input,
        output,
        cache_read: input / 10.0,
    }
}

/// Exact model ids only: a guessed family rate would present a wrong number as
/// an estimate, so an unlisted model has no estimate at all.
const MODEL_RATES: &[(&str, ModelRates)] = &[
    (
        "claude-fable-5-1",
        ModelRates {
            input: 10.0,
            output: 50.0,
            cache_read: 0.25,
        },
    ),
    (
        "claude-orchid-5-1",
        ModelRates {
            input: 10.0,
            output: 50.0,
            cache_read: 0.25,
        },
    ),
    ("claude-fable-5", rates(10.0, 50.0)),
    (
        "claude-opus-5-5",
        ModelRates {
            input: 4.0,
            output: 20.0,
            cache_read: 0.20,
        },
    ),
    ("claude-opus-5", rates(5.0, 25.0)),
    ("claude-opus-4-8", rates(5.0, 25.0)),
    ("claude-opus-4-7", rates(5.0, 25.0)),
    ("claude-opus-4-6", rates(5.0, 25.0)),
    ("claude-opus-4-5", rates(5.0, 25.0)),
    ("claude-opus-4-1", rates(15.0, 75.0)),
    ("claude-opus-4-0", rates(15.0, 75.0)),
    ("claude-opus-4", rates(15.0, 75.0)),
    ("claude-sonnet-5", rates(2.0, 10.0)),
    ("claude-sonnet-4-6", rates(3.0, 15.0)),
    ("claude-sonnet-4-5", rates(3.0, 15.0)),
    ("claude-sonnet-4-0", rates(3.0, 15.0)),
    ("claude-sonnet-4", rates(3.0, 15.0)),
    ("claude-3-7-sonnet", rates(3.0, 15.0)),
    ("claude-haiku-4-5", rates(1.0, 5.0)),
    ("claude-3-5-haiku", rates(0.8, 4.0)),
    ("claude-3-haiku", rates(0.25, 1.25)),
];

pub(crate) fn estimate_cost_usd_with_cache(
    model: &str,
    input_tokens: u32,
    output_tokens: u32,
    prompt_cache: Option<PromptCacheUsage>,
) -> Option<f64> {
    let rates = model_rates(model)?;
    let cache = prompt_cache.unwrap_or_default();
    let input_usd = f64::from(input_tokens) * rates.input
        + f64::from(cache.read_input_tokens) * rates.cache_read
        + f64::from(cache.creation_input_tokens) * rates.input * CACHE_CREATION_INPUT_RATE;
    Some((input_usd + f64::from(output_tokens) * rates.output) / 1_000_000.0)
}

fn model_rates(model: &str) -> Option<&'static ModelRates> {
    let id = canonical_model_id(model);
    MODEL_RATES
        .iter()
        .find(|(known, _)| *known == id)
        .map(|(_, rates)| rates)
}

/// `anthropic:claude-haiku-4-5-20251001` → `claude-haiku-4-5`.
fn canonical_model_id(model: &str) -> String {
    let id = strip_provider_prefix(model.trim()).to_ascii_lowercase();
    match id.rsplit_once('-') {
        Some((base, date)) if is_snapshot_date(date) => base.to_string(),
        _ => id,
    }
}

fn is_snapshot_date(segment: &str) -> bool {
    segment.len() == 8 && segment.bytes().all(|byte| byte.is_ascii_digit())
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
    #[serde(default)]
    pub(crate) cache_read_input_tokens: Option<u32>,
    #[serde(default)]
    pub(crate) cache_creation_input_tokens: Option<u32>,
}
