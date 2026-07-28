use anyhow::Result;
use kuzushi_core::{RuntimeConfig, ScanCancellation, V2Config};
use std::path::Path;
use std::path::PathBuf;

use super::bridge_process::default_langgraph_bridge_command;

#[derive(Debug, Clone)]
pub struct LangGraphRuntime {
    pub(crate) command: Vec<String>,
    pub(crate) api_key_env: String,
    pub(crate) api_key: Option<String>,
    pub(crate) base_url: Option<String>,
    pub(crate) thinking_level: Option<String>,
    pub(crate) oauth_credentials_path: PathBuf,
    pub(crate) oauth_allow_env_token: bool,
    pub(crate) cancellation: Option<ScanCancellation>,
    pub(crate) retry: BridgeRetryPolicy,
}

/// Retry policy for transient bridge failures (429/5xx/transport), sourced
/// from `runtime.bridge_retry_attempts` / `runtime.bridge_retry_backoff_ms`.
/// The backoff doubles per attempt so a per-minute provider quota can be
/// outwaited by raising the base instead of the attempt count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeRetryPolicy {
    pub(crate) attempts: Option<usize>,
    pub(crate) backoff_ms: u64,
}

const DEFAULT_BRIDGE_RETRY_ATTEMPTS: usize = 3;
const DEFAULT_BRIDGE_RETRY_BACKOFF_MS: u64 = 250;
const MAX_BRIDGE_RETRY_DELAY_MS: u64 = 120_000;

impl Default for BridgeRetryPolicy {
    fn default() -> Self {
        Self {
            attempts: None,
            backoff_ms: DEFAULT_BRIDGE_RETRY_BACKOFF_MS,
        }
    }
}

impl BridgeRetryPolicy {
    fn from_runtime_config(runtime: &RuntimeConfig) -> Self {
        Self {
            attempts: runtime
                .bridge_retry_attempts
                .map(|attempts| attempts.max(1) as usize),
            backoff_ms: runtime
                .bridge_retry_backoff_ms
                .filter(|ms| *ms > 0)
                .unwrap_or(DEFAULT_BRIDGE_RETRY_BACKOFF_MS),
        }
    }

    pub(crate) fn attempts(&self) -> usize {
        self.attempts.unwrap_or(DEFAULT_BRIDGE_RETRY_ATTEMPTS)
    }

    pub(crate) fn rate_limit_attempts(&self) -> usize {
        self.attempts.unwrap_or(5)
    }

    pub(crate) fn delay_ms(&self, attempt: usize) -> u64 {
        let doublings = attempt.saturating_sub(1).min(16) as u32;
        self.backoff_ms
            .saturating_mul(1_u64 << doublings)
            .min(MAX_BRIDGE_RETRY_DELAY_MS)
    }
}

impl LangGraphRuntime {
    pub fn from_config(config: &V2Config, source_root: impl AsRef<Path>) -> Result<Self> {
        Self::from_runtime_config(&config.runtime, source_root)
    }

    pub fn from_runtime_config(
        runtime: &RuntimeConfig,
        source_root: impl AsRef<Path>,
    ) -> Result<Self> {
        let command = runtime
            .langgraph_bridge_command
            .clone()
            .unwrap_or_else(|| default_langgraph_bridge_command(source_root.as_ref()));
        if command.is_empty() {
            anyhow::bail!("LangGraph bridge command is empty");
        }

        let api_key = std::env::var(&runtime.api_key_env)
            .ok()
            .filter(|value| !value.trim().is_empty());
        let oauth = runtime.anthropic_oauth.clone().unwrap_or_default();
        let oauth_credentials_path = crate::oauth::resolve_credentials_path(&oauth)?;

        Ok(Self {
            command,
            api_key_env: runtime.api_key_env.clone(),
            api_key,
            base_url: runtime.base_url.clone(),
            thinking_level: runtime
                .thinking_level
                .clone()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            oauth_credentials_path,
            oauth_allow_env_token: oauth.allow_env_token,
            cancellation: None,
            retry: BridgeRetryPolicy::from_runtime_config(runtime),
        })
    }

    pub fn command(&self) -> &[String] {
        &self.command
    }

    pub fn with_thinking_level(mut self, thinking_level: Option<String>) -> Self {
        self.thinking_level = thinking_level
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self
    }

    pub fn with_cancellation(mut self, cancellation: ScanCancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_retry_policy_keeps_prior_schedule() {
        let policy = BridgeRetryPolicy::default();
        assert_eq!(policy.attempts(), 3);
        assert_eq!(policy.delay_ms(1), 250);
        assert_eq!(policy.delay_ms(2), 500);
        assert_eq!(policy.delay_ms(3), 1_000);
    }

    #[test]
    fn configured_retry_policy_reads_runtime_config() {
        let runtime = RuntimeConfig {
            bridge_retry_attempts: Some(6),
            bridge_retry_backoff_ms: Some(20_000),
            ..RuntimeConfig::default()
        };

        let policy = BridgeRetryPolicy::from_runtime_config(&runtime);

        assert_eq!(policy.attempts(), 6);
        assert_eq!(policy.delay_ms(1), 20_000);
        assert_eq!(policy.delay_ms(2), 40_000);
        assert_eq!(policy.delay_ms(3), 80_000);
        assert_eq!(policy.delay_ms(4), 120_000, "delay is capped");
    }

    #[test]
    fn degenerate_retry_config_clamps_to_safe_floors() {
        let runtime = RuntimeConfig {
            bridge_retry_attempts: Some(0),
            bridge_retry_backoff_ms: Some(0),
            ..RuntimeConfig::default()
        };

        let policy = BridgeRetryPolicy::from_runtime_config(&runtime);

        assert_eq!(policy.attempts(), 1);
        assert_eq!(policy.delay_ms(1), 250);
    }
}
