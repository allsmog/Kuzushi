use super::prelude::*;
use super::*;

pub(crate) const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

pub(crate) const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";

pub(crate) const DEFAULT_OAUTH_BETA: &str = "oauth-2025-04-20";

pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 120;

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
    pub(crate) client: reqwest::Client,
    pub(crate) base_url: String,
    pub(crate) token: String,
    pub(crate) anthropic_version: String,
    pub(crate) anthropic_beta: String,
    pub(crate) max_tokens: u32,
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
