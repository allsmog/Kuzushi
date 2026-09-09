use anyhow::{Context, Result};
use kuzushi_core::{
    append_structured_output_contract, AgentQueryRequest, AgentQueryResponse, ModelTokenUsage,
    Observed,
};
use serde_json::{json, Value};
use std::time::Duration;

use super::options::{
    AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions, DEFAULT_ANTHROPIC_VERSION,
    DEFAULT_BASE_URL, DEFAULT_OAUTH_BETA, DEFAULT_TIMEOUT_SECS,
};
use super::response::{maybe_parse_json, strip_provider_prefix, ApiResponse};

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

    pub fn from_default_token_path() -> Result<Self> {
        let home = super::response::dirs_home()?;
        let path = home.join(".claude").join("remote").join(".oauth_token");
        Self::new(AnthropicOAuthRuntimeOptions::from_token_file(path)?)
    }

    pub(crate) async fn send_messages_observed(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        let model = strip_provider_prefix(&request.model);
        let max_tokens = request.max_output_tokens.unwrap_or(self.max_tokens);
        let body = anthropic_messages_body(&model, max_tokens, &request);
        let resp = self.send_anthropic_messages_request(&body).await?;
        parse_anthropic_messages_http_response_observed(&model, resp).await
    }

    pub(crate) async fn send_anthropic_messages_request(
        &self,
        body: &Value,
    ) -> Result<reqwest::Response> {
        self.client
            .post(format!("{}/v1/messages", self.base_url))
            .header("authorization", format!("Bearer {}", self.token))
            .header("anthropic-version", &self.anthropic_version)
            .header("anthropic-beta", &self.anthropic_beta)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Anthropic OAuth: could not send /v1/messages")
    }
}

async fn parse_anthropic_messages_http_response_observed(
    model: &str,
    resp: reqwest::Response,
) -> Result<Observed<AgentQueryResponse>> {
    let status = resp.status();
    let raw = read_anthropic_response_body(resp).await?;
    ensure_anthropic_success(status, &raw)?;
    parse_anthropic_messages_response_observed(model, &raw)
}

pub(crate) async fn read_anthropic_response_body(resp: reqwest::Response) -> Result<String> {
    resp.text()
        .await
        .context("Anthropic OAuth: could not read response body")
}

pub(crate) fn ensure_anthropic_success(status: reqwest::StatusCode, _raw: &str) -> Result<()> {
    if !status.is_success() {
        anyhow::bail!("Anthropic OAuth: HTTP {status}");
    }
    Ok(())
}

pub(crate) fn anthropic_messages_body(
    model: &str,
    max_tokens: u32,
    request: &AgentQueryRequest,
) -> Value {
    let system_prompt = append_structured_output_contract(
        &request.system_prompt,
        request.structured_output.as_ref(),
    );
    json!({
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{ "role": "user", "content": anthropic_user_content(request) }],
    })
}

/// The user turn as one plain string, or — when the request declares a
/// verified cacheable prefix — as a cache-marked text block followed by the
/// remainder, so every later call sharing that prefix reads it from cache.
fn anthropic_user_content(request: &AgentQueryRequest) -> Value {
    let Some((prefix, remainder)) = request.prompt_cache_split() else {
        return Value::String(request.prompt.clone());
    };
    let mut blocks = vec![json!({
        "type": "text",
        "text": prefix,
        "cache_control": { "type": "ephemeral" },
    })];
    if !remainder.is_empty() {
        blocks.push(json!({ "type": "text", "text": remainder }));
    }
    Value::Array(blocks)
}

#[cfg(test)]
pub(crate) fn parse_anthropic_messages_response(
    model: &str,
    raw: &str,
) -> Result<AgentQueryResponse> {
    parse_anthropic_messages_response_observed(model, raw).map(Observed::into_value)
}

fn parse_anthropic_messages_response_observed(
    model: &str,
    raw: &str,
) -> Result<Observed<AgentQueryResponse>> {
    let parsed: ApiResponse = serde_json::from_str(raw)
        .map_err(|_| anyhow::anyhow!("Anthropic OAuth: could not parse response"))?;
    let usage = parsed
        .usage
        .as_ref()
        .map_or_else(ModelTokenUsage::unavailable_call, |usage| {
            ModelTokenUsage::from_reported_options(
                usage.input_tokens.map(u64::from),
                usage.output_tokens.map(u64::from),
            )
        });
    let text = super::response::anthropic_response_text(&parsed);
    let structured = maybe_parse_json(&text);
    let (input_tokens, output_tokens) = super::response::anthropic_response_usage(&parsed);
    let prompt_cache = super::response::anthropic_response_prompt_cache(&parsed);
    let estimated_cost_usd = super::response::estimate_cost_usd_with_cache(
        model,
        input_tokens,
        output_tokens,
        prompt_cache,
    );
    let stop_reason = parsed.stop_reason.clone();
    let truncated = stop_reason.as_deref() == Some("max_tokens");

    Ok(Observed::new(
        AgentQueryResponse {
            text,
            structured,
            cost_usd: 0.0,
            cost_usd_reported: false,
            estimated_cost_usd,
            input_tokens,
            output_tokens,
            prompt_cache,
            truncated,
            stop_reason,
        },
        usage,
    ))
}

#[cfg(test)]
mod observed_usage_tests {
    use super::*;

    #[test]
    fn provider_reported_zero_usage_is_preserved() {
        let observed = parse_anthropic_messages_response_observed(
            "claude-test",
            r#"{"content":[],"usage":{"input_tokens":0,"output_tokens":0}}"#,
        )
        .unwrap();

        assert_eq!(observed.usage.observed_counts(), (Some(0), Some(0)));
        assert!(observed.usage.is_complete());
    }

    #[test]
    fn absent_usage_is_not_synthesized_as_zero() {
        let observed =
            parse_anthropic_messages_response_observed("claude-test", r#"{"content":[]}"#).unwrap();

        assert_eq!(observed.usage.observed_counts(), (None, None));
        assert!(observed.usage.is_unavailable());
    }

    #[test]
    fn partial_usage_keeps_missing_direction_unavailable() {
        let observed = parse_anthropic_messages_response_observed(
            "claude-test",
            r#"{"content":[],"usage":{"input_tokens":5}}"#,
        )
        .unwrap();

        assert_eq!(observed.usage.observed_counts(), (Some(5), None));
        assert!(!observed.usage.is_complete());
    }

    #[test]
    fn parse_errors_do_not_echo_provider_response() {
        let sentinel = "raw-model-response-sentinel";
        let raw = format!(r#"{{"content":"{sentinel}"}}"#);
        let error = format!(
            "{:#}",
            parse_anthropic_messages_response_observed("claude-test", &raw).unwrap_err()
        );

        assert!(error.contains("could not parse response"));
        assert!(!error.contains(sentinel));
    }
}
