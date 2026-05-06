//! Native Rust [`AgentRuntime`] backed by Anthropic OAuth.
//!
//! Talks directly to `api.anthropic.com` (or any compatible base URL)
//! via `reqwest` with `rustls`. Authenticates with a long-lived OAuth
//! access token of the form `sk-ant-oat01-...` passed in
//! [`AnthropicOAuthRuntimeOptions::token`] or read from a file path.
//!
//! No Node.js bridge, no pi-ai SDK. Subprocesses are zero — every
//! query is a single HTTPS round-trip. The runtime is `Send + Sync`
//! and cheap to clone.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_core::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolPolicy, ModelTier, TriageOutcome,
    TriageRequest, TriageVerdict,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_OAUTH_BETA: &str = "oauth-2025-04-20";
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Construction options for [`AnthropicOAuthRuntime`].
#[derive(Debug, Clone)]
pub struct AnthropicOAuthRuntimeOptions {
    /// OAuth access token. Leading/trailing whitespace is stripped.
    pub token: String,
    /// Override `https://api.anthropic.com`. Useful for proxies and
    /// recording tests.
    pub base_url: Option<String>,
    /// `anthropic-version` header (defaults to `2023-06-01`).
    pub anthropic_version: Option<String>,
    /// `anthropic-beta` header (defaults to `oauth-2025-04-20`).
    pub anthropic_beta: Option<String>,
    /// Per-request HTTPS timeout. Defaults to 120 s.
    pub timeout: Option<Duration>,
    /// Cap on `max_tokens` per request. Defaults to 4096 — adapters
    /// that need long replies should override.
    pub max_tokens: Option<u32>,
}

impl AnthropicOAuthRuntimeOptions {
    pub fn from_token(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            base_url: None,
            anthropic_version: None,
            anthropic_beta: None,
            timeout: None,
            max_tokens: None,
        }
    }

    /// Read the token from a file (single-line, may have trailing
    /// newline). Suitable for hosts that expose the OAuth token at a
    /// fixed path.
    pub fn from_token_file(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).with_context(|| {
            format!(
                "could not read OAuth token from {}",
                path.as_ref().display()
            )
        })?;
        Ok(Self::from_token(raw.trim()))
    }
}

#[derive(Clone)]
pub struct AnthropicOAuthRuntime {
    client: reqwest::Client,
    base_url: String,
    token: String,
    anthropic_version: String,
    anthropic_beta: String,
    max_tokens: u32,
}

impl std::fmt::Debug for AnthropicOAuthRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicOAuthRuntime")
            .field("base_url", &self.base_url)
            .field("anthropic_version", &self.anthropic_version)
            .field("anthropic_beta", &self.anthropic_beta)
            .field("max_tokens", &self.max_tokens)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl AnthropicOAuthRuntime {
    pub fn new(options: AnthropicOAuthRuntimeOptions) -> Result<Self> {
        let token = options.token.trim().to_string();
        if token.is_empty() {
            anyhow::bail!("AnthropicOAuthRuntime: OAuth token is empty");
        }
        let timeout = options
            .timeout
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("could not build Anthropic OAuth HTTP client")?;
        Ok(Self {
            client,
            base_url: options
                .base_url
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            token,
            anthropic_version: options
                .anthropic_version
                .unwrap_or_else(|| DEFAULT_ANTHROPIC_VERSION.to_string()),
            anthropic_beta: options
                .anthropic_beta
                .unwrap_or_else(|| DEFAULT_OAUTH_BETA.to_string()),
            max_tokens: options.max_tokens.unwrap_or(4096),
        })
    }

    /// Construct from `~/.claude/remote/.oauth_token` (the path the
    /// Claude Code host exposes the token at). Errors when the file
    /// is absent or empty.
    pub fn from_default_token_path() -> Result<Self> {
        let home = dirs_home()?;
        let path = home.join(".claude").join("remote").join(".oauth_token");
        Self::new(AnthropicOAuthRuntimeOptions::from_token_file(path)?)
    }

    async fn send_messages(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        // Anthropic accepts `provider:model` in the model field, but
        // we strip the provider prefix here so the backend sees just
        // `claude-...`. This mirrors the convention the bridge enforces.
        let model = strip_provider_prefix(&request.model);
        let body = json!({
            "model": model,
            "max_tokens": self.max_tokens,
            "system": request.system_prompt,
            "messages": [{ "role": "user", "content": request.prompt }],
        });

        let resp = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .header("authorization", format!("Bearer {}", self.token))
            .header("anthropic-version", &self.anthropic_version)
            .header("anthropic-beta", &self.anthropic_beta)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Anthropic OAuth: could not send /v1/messages")?;

        let status = resp.status();
        let raw = resp
            .text()
            .await
            .context("Anthropic OAuth: could not read response body")?;
        if !status.is_success() {
            anyhow::bail!("Anthropic OAuth: HTTP {status}: {raw}");
        }
        let parsed: ApiResponse = serde_json::from_str(&raw)
            .with_context(|| format!("Anthropic OAuth: could not parse response: {raw}"))?;

        let text = parsed
            .content
            .iter()
            .filter_map(|block| match block {
                ApiContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("");
        let structured = maybe_parse_json(&text);

        let (input_tokens, output_tokens) = parsed
            .usage
            .as_ref()
            .map(|u| (u.input_tokens, u.output_tokens))
            .unwrap_or((0, 0));
        let cost_usd = estimate_cost_usd(&model, input_tokens, output_tokens);

        Ok(AgentQueryResponse {
            text,
            structured,
            cost_usd,
            input_tokens,
            output_tokens,
        })
    }
}

/// Per-model rate table (USD per token). Numbers are approximate
/// public prices and are recomputed against the response's
/// `usage.input_tokens` / `usage.output_tokens` per call. Operators
/// who want exact billing should rely on Anthropic's invoiced totals;
/// this is only used to drive in-process cost caps.
fn estimate_cost_usd(model: &str, input_tokens: u32, output_tokens: u32) -> f64 {
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

/// Resolve a tier handle to a concrete Anthropic model name. Operators
/// that want a different mapping (e.g. pin Cheap to a specific Haiku
/// minor version) override via the `configured` argument.
fn anthropic_model_for_tier(tier: ModelTier, configured: &str) -> String {
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

fn strip_provider_prefix(model: &str) -> String {
    match model.split_once(':') {
        Some((_, rest)) if !rest.is_empty() => rest.to_string(),
        _ => model.to_string(),
    }
}

fn dirs_home() -> Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .context("could not resolve home directory (HOME / USERPROFILE)")
}

fn maybe_parse_json(text: &str) -> Option<Value> {
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
struct ApiResponse {
    #[serde(default)]
    content: Vec<ApiContentBlock>,
    #[serde(default)]
    usage: Option<ApiUsage>,
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ApiContentBlock {
    Text {
        text: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct ApiUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

const TRIAGE_SYSTEM_PROMPT: &str = "You are Kuzushi's security triage agent. \
Reply only with JSON of the shape \
{\"verdict\":\"true_positive|false_positive|needs_review\",\"confidence\":0.0-1.0,\"rationale\":\"<short evidence-based reason>\"}.";

#[async_trait]
impl AgentRuntime for AnthropicOAuthRuntime {
    fn model_for_tier(&self, tier: ModelTier, configured: &str) -> String {
        anthropic_model_for_tier(tier, configured)
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        // Build a *current-thread* runtime so this call doesn't depend
        // on being driven from inside an async context. Slightly more
        // expensive than awaiting from an async caller — adapters that
        // are already async should call `query` directly.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("AnthropicOAuthRuntime: could not start a tokio runtime")?;
        runtime.block_on(self.send_messages(request))
    }

    async fn query(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.send_messages(request).await
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("AnthropicOAuthRuntime: could not start a tokio runtime")?;
        runtime.block_on(self.triage_finding(request))
    }

    async fn triage_finding(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let prompt = build_triage_prompt(&request)?;
        let response = self
            .send_messages(AgentQueryRequest {
                model: request.model,
                cwd: request.cwd,
                system_prompt: TRIAGE_SYSTEM_PROMPT.to_string(),
                prompt,
                tool_policy: AgentToolPolicy::default(),
            })
            .await?;

        let call_cost = response.cost_usd;

        if let Some(structured) = response.structured.as_ref() {
            if let Ok(mut outcome) = serde_json::from_value::<TriageOutcome>(structured.clone()) {
                outcome.cost_usd = call_cost;
                return Ok(clamp_outcome(outcome));
            }
        }

        if !response.text.is_empty() {
            if let Ok(mut outcome) = serde_json::from_str::<TriageOutcome>(&response.text) {
                outcome.cost_usd = call_cost;
                return Ok(clamp_outcome(outcome));
            }
            return Ok(TriageOutcome {
                verdict: TriageVerdict::NeedsReview,
                confidence: 0.25,
                rationale: response.text,
                cost_usd: call_cost,
            });
        }

        Ok(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.0,
            rationale: "AnthropicOAuthRuntime returned no triage content".to_string(),
            cost_usd: call_cost,
        })
    }
}

fn build_triage_prompt(request: &TriageRequest) -> Result<String> {
    let json =
        serde_json::to_string_pretty(&request.finding).context("could not serialize finding")?;
    let template = request
        .prompt_template
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(
            "Triage this SAST finding. Be conservative; use needs_review when evidence is incomplete.",
        );
    Ok(format!("{template}\n\nFinding JSON:\n{json}"))
}

fn clamp_outcome(mut outcome: TriageOutcome) -> TriageOutcome {
    outcome.confidence = outcome.confidence.clamp(0.0, 1.0);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_from_token_strips_whitespace() {
        let opts = AnthropicOAuthRuntimeOptions::from_token("  sk-ant-oat01-AAA  \n");
        let runtime = AnthropicOAuthRuntime::new(opts).unwrap();
        assert!(runtime.token.starts_with("sk-ant-oat01-"));
        assert!(!runtime.token.ends_with(char::is_whitespace));
    }

    #[test]
    fn options_reject_empty_token() {
        let err = AnthropicOAuthRuntime::new(AnthropicOAuthRuntimeOptions::from_token("   "))
            .unwrap_err();
        assert!(err.to_string().contains("token is empty"));
    }

    #[test]
    fn from_token_file_reads_single_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("tok");
        std::fs::write(&path, "sk-ant-oat01-XYZ\n").unwrap();
        let opts = AnthropicOAuthRuntimeOptions::from_token_file(&path).unwrap();
        assert_eq!(opts.token, "sk-ant-oat01-XYZ");
    }

    #[test]
    fn from_token_file_errors_when_missing() {
        let err = AnthropicOAuthRuntimeOptions::from_token_file("/no/such/path/token").unwrap_err();
        assert!(err.to_string().contains("could not read OAuth token"));
    }

    #[test]
    fn debug_redacts_token() {
        let runtime = AnthropicOAuthRuntime::new(AnthropicOAuthRuntimeOptions::from_token(
            "sk-ant-oat01-SECRET",
        ))
        .unwrap();
        let s = format!("{runtime:?}");
        assert!(!s.contains("SECRET"));
        assert!(s.contains("redacted"));
    }

    #[test]
    fn strip_provider_prefix_removes_provider() {
        assert_eq!(
            strip_provider_prefix("anthropic:claude-opus-4-7"),
            "claude-opus-4-7"
        );
        assert_eq!(strip_provider_prefix("claude-haiku"), "claude-haiku");
        assert_eq!(strip_provider_prefix(""), "");
    }

    #[test]
    fn maybe_parse_json_handles_fenced_response() {
        let v = maybe_parse_json("```json\n{\"k\": 1}\n```").unwrap();
        assert_eq!(v["k"], 1);
    }

    #[test]
    fn maybe_parse_json_handles_unfenced_object() {
        let v = maybe_parse_json("{\"k\": 2}").unwrap();
        assert_eq!(v["k"], 2);
    }

    #[test]
    fn maybe_parse_json_extracts_largest_balanced_block() {
        let v = maybe_parse_json("Here is the result:\n{\"k\": 3}\nThanks").unwrap();
        assert_eq!(v["k"], 3);
    }

    #[test]
    fn maybe_parse_json_returns_none_for_plain_text() {
        assert!(maybe_parse_json("just words").is_none());
    }

    #[test]
    fn build_triage_prompt_includes_template_and_finding() {
        use kuzushi_core::{Finding, Severity};
        let req = TriageRequest {
            model: "anthropic:claude-haiku-4-5-20251001".to_string(),
            cwd: ".".into(),
            finding: Finding::new_tool("test", "rule", "src/x.c", 1, None, Severity::High, "msg"),
            prompt_template: Some("Custom prompt".to_string()),
        };
        let prompt = build_triage_prompt(&req).unwrap();
        assert!(prompt.contains("Custom prompt"));
        assert!(prompt.contains("Finding JSON:"));
        assert!(prompt.contains("rule"));
    }

    #[test]
    fn clamp_outcome_caps_confidence() {
        let mut outcome = TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 1.5,
            rationale: "x".to_string(),
            ..Default::default()
        };
        outcome = clamp_outcome(outcome);
        assert_eq!(outcome.confidence, 1.0);
        outcome.confidence = -0.3;
        outcome = clamp_outcome(outcome);
        assert_eq!(outcome.confidence, 0.0);
    }

    // ----- cost estimation -----------------------------------------

    #[test]
    fn cost_estimate_uses_haiku_rates_for_haiku_models() {
        let cost = estimate_cost_usd("claude-haiku-4-5-20251001", 1000, 1000);
        // Haiku: $0.0008/k in + $0.004/k out × 1k each.
        assert!((cost - (0.0008 + 0.004)).abs() < 1e-9);
    }

    #[test]
    fn cost_estimate_uses_sonnet_rates_for_sonnet_models() {
        let cost = estimate_cost_usd("claude-sonnet-4-6", 1000, 1000);
        assert!((cost - (0.003 + 0.015)).abs() < 1e-9);
    }

    #[test]
    fn cost_estimate_uses_opus_rates_for_opus_models() {
        let cost = estimate_cost_usd("claude-opus-4-7", 1000, 1000);
        assert!((cost - (0.015 + 0.075)).abs() < 1e-9);
    }

    #[test]
    fn cost_estimate_falls_back_to_sonnet_rates_for_unknown_models() {
        let unknown = estimate_cost_usd("some-future-model", 1000, 1000);
        let sonnet = estimate_cost_usd("claude-sonnet-4-6", 1000, 1000);
        assert!((unknown - sonnet).abs() < 1e-9);
    }

    #[test]
    fn cost_estimate_zero_when_no_tokens() {
        assert_eq!(estimate_cost_usd("claude-haiku-4-5", 0, 0), 0.0);
    }

    // ----- model_for_tier ------------------------------------------

    #[test]
    fn model_for_tier_promotes_haiku_when_cheap_requested_with_sonnet() {
        let resolved = anthropic_model_for_tier(ModelTier::Cheap, "anthropic:claude-sonnet-4-6");
        assert!(resolved.contains("haiku"));
    }

    #[test]
    fn model_for_tier_promotes_opus_when_deep_requested_with_haiku() {
        let resolved =
            anthropic_model_for_tier(ModelTier::Deep, "anthropic:claude-haiku-4-5-20251001");
        assert!(resolved.contains("opus"));
    }

    #[test]
    fn model_for_tier_keeps_configured_when_already_correct_tier() {
        let resolved =
            anthropic_model_for_tier(ModelTier::Cheap, "anthropic:claude-haiku-4-5-20251001");
        assert_eq!(resolved, "claude-haiku-4-5-20251001");
    }

    #[test]
    fn runtime_model_for_tier_dispatches_through_anthropic_helper() {
        let runtime = AnthropicOAuthRuntime::new(AnthropicOAuthRuntimeOptions::from_token(
            "sk-ant-oat01-XYZ",
        ))
        .unwrap();
        // Ask for Cheap on an Opus-configured model — should down-shift.
        let model = runtime.model_for_tier(ModelTier::Cheap, "anthropic:claude-opus-4-7");
        assert!(model.contains("haiku"));
    }
}
