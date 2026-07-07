//! Agent-runtime selection.
//!
//! One place that turns `config.runtime.agent_runtime` into a concrete
//! `AgentRuntime`. `bridge` (default) builds the Node LangGraph runtime;
//! `native` builds the in-process `AnthropicOAuthRuntime`. Selection is
//! explicit: a `native` selection with no usable OAuth credential is a hard
//! error, never a silent downgrade to the bridge (see the no-silent-fallback
//! policy in `CLAUDE.md`).
//!
//! Call sites migrate to this factory to make the flag live per mode. During
//! parity testing both runtimes ship and the default stays `bridge`.

use anyhow::Result;
use kuzushi_core::{AgentRuntime, AgentRuntimeSelector, V2Config};
use std::path::Path;

use crate::anthropic_oauth::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
use crate::langgraph_runtime::LangGraphRuntime;
use crate::oauth::native_anthropic_access_token;

/// Build the agent runtime selected by `config.runtime.agent_runtime`.
pub fn build_agent_runtime(
    config: &V2Config,
    source_root: impl AsRef<Path>,
) -> Result<Box<dyn AgentRuntime>> {
    match config.runtime.agent_runtime {
        AgentRuntimeSelector::Bridge => {
            Ok(Box::new(LangGraphRuntime::from_config(config, source_root)?))
        }
        AgentRuntimeSelector::Native => Ok(Box::new(build_native_runtime(config)?)),
    }
}

fn build_native_runtime(config: &V2Config) -> Result<AnthropicOAuthRuntime> {
    let oauth_cfg = config.runtime.anthropic_oauth.clone().unwrap_or_default();
    let token = native_anthropic_access_token(&oauth_cfg)?;
    let mut options = AnthropicOAuthRuntimeOptions::from_token(token);
    // Honour an operator-configured base URL (also lets integration tests point
    // the native runtime at a mock server).
    options.base_url = config.runtime.base_url.clone();
    AnthropicOAuthRuntime::new(options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::AnthropicOauthConfig;

    fn config_with(selector: AgentRuntimeSelector, creds: Option<std::path::PathBuf>) -> V2Config {
        let mut config = V2Config::default();
        config.runtime.agent_runtime = selector;
        if let Some(path) = creds {
            config.runtime.anthropic_oauth = Some(AnthropicOauthConfig {
                credentials_path: Some(path),
                allow_env_token: false,
            });
        }
        config
    }

    #[test]
    fn bridge_selection_builds_a_runtime() {
        // Default selector is bridge; the factory builds the LangGraph runtime
        // without needing any OAuth credential.
        let config = config_with(AgentRuntimeSelector::Bridge, None);
        let runtime = build_agent_runtime(&config, std::env::temp_dir());
        assert!(runtime.is_ok(), "bridge runtime should build");
    }

    #[test]
    fn native_selection_builds_from_valid_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let creds = tmp.path().join("oauth-credentials.json");
        // Far-future expiry so the readiness probe reports Ready.
        std::fs::write(
            &creds,
            r#"{"anthropic":{"access":"sk-ant-oat01-NATIVE","refresh":"r","expires":33227740800000}}"#,
        )
        .unwrap();
        let config = config_with(AgentRuntimeSelector::Native, Some(creds));
        let runtime = build_agent_runtime(&config, std::env::temp_dir())
            .expect("native runtime should build from valid credentials");
        assert!(runtime.supports_tools(), "native supports the tool loop");
    }

    #[test]
    fn native_selection_errors_without_credentials_no_silent_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist.json");
        let config = config_with(AgentRuntimeSelector::Native, Some(missing));
        let err = build_agent_runtime(&config, std::env::temp_dir())
            .map(|_| ())
            .expect_err("native must not silently fall back to the bridge");
        let message = err.to_string();
        assert!(
            message.contains("native agent runtime") && message.contains("no Anthropic OAuth"),
            "error should be actionable, got: {message}"
        );
    }
}
