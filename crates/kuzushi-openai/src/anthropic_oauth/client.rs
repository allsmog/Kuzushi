use anyhow::{Context, Result};
use kuzushi_core::{append_structured_output_contract, AgentQueryRequest, AgentQueryResponse};
use serde_json::{json, Value};
use std::time::Duration;

use super::options::{
    AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions, DEFAULT_ANTHROPIC_VERSION,
    DEFAULT_BASE_URL, DEFAULT_OAUTH_BETA, DEFAULT_TIMEOUT_SECS,
};
use super::response::{estimate_cost_usd, maybe_parse_json, strip_provider_prefix, ApiResponse};

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

    pub(crate) async fn send_messages(
        &self,
        request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        let model = strip_provider_prefix(&request.model);
        let max_tokens = request.max_output_tokens.unwrap_or(self.max_tokens);
        let body = anthropic_messages_body(&model, max_tokens, &request);
        let resp = self.send_anthropic_messages_request(&body).await?;
        parse_anthropic_messages_http_response(&model, resp).await
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

pub(crate) async fn parse_anthropic_messages_http_response(
    model: &str,
    resp: reqwest::Response,
) -> Result<AgentQueryResponse> {
    let status = resp.status();
    let raw = read_anthropic_response_body(resp).await?;
    ensure_anthropic_success(status, &raw)?;
    parse_anthropic_messages_response(model, &raw)
}

pub(crate) async fn read_anthropic_response_body(resp: reqwest::Response) -> Result<String> {
    resp.text()
        .await
        .context("Anthropic OAuth: could not read response body")
}

pub(crate) fn ensure_anthropic_success(status: reqwest::StatusCode, raw: &str) -> Result<()> {
    if !status.is_success() {
        anyhow::bail!("Anthropic OAuth: HTTP {status}: {raw}");
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
        "messages": [{ "role": "user", "content": request.prompt }],
    })
}

pub(crate) fn parse_anthropic_messages_response(
    model: &str,
    raw: &str,
) -> Result<AgentQueryResponse> {
    let parsed: ApiResponse = serde_json::from_str(raw)
        .with_context(|| format!("Anthropic OAuth: could not parse response: {raw}"))?;
    let text = super::response::anthropic_response_text(&parsed);
    let structured = maybe_parse_json(&text);
    let (input_tokens, output_tokens) = super::response::anthropic_response_usage(&parsed);
    let estimated_cost_usd = estimate_cost_usd(model, input_tokens, output_tokens);
    let stop_reason = parsed.stop_reason.clone();
    let truncated = stop_reason.as_deref() == Some("max_tokens");

    Ok(AgentQueryResponse {
        text,
        structured,
        cost_usd: 0.0,
        cost_usd_reported: false,
        estimated_cost_usd,
        input_tokens,
        output_tokens,
        truncated,
        stop_reason,
    })
}
