use anyhow::Result;
use kuzushi_core::{RuntimeConfig, V2Config};
use std::env;
use std::path::Path;

use crate::default_bridge_command;

#[derive(Debug, Clone)]
pub struct PiAgentCoreRuntime {
    pub(crate) command: Vec<String>,
    pub(crate) api_key_env: String,
    pub(crate) api_key: Option<String>,
    pub(crate) base_url: Option<String>,
    pub(crate) thinking_level: Option<String>,
}

impl PiAgentCoreRuntime {
    pub fn from_config(config: &V2Config, source_root: impl AsRef<Path>) -> Result<Self> {
        Self::from_runtime_config(&config.runtime, source_root)
    }

    pub fn from_runtime_config(
        runtime: &RuntimeConfig,
        source_root: impl AsRef<Path>,
    ) -> Result<Self> {
        let command = runtime
            .agent_bridge_command
            .clone()
            .unwrap_or_else(|| default_bridge_command(source_root.as_ref()));
        if command.is_empty() {
            anyhow::bail!("pi-agent-core bridge command is empty");
        }

        let api_key = env::var(&runtime.api_key_env)
            .ok()
            .filter(|value| !value.trim().is_empty());

        Ok(Self {
            command,
            api_key_env: runtime.api_key_env.clone(),
            api_key,
            base_url: runtime.base_url.clone(),
            thinking_level: env::var("KUZUSHI_THINKING_LEVEL")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
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
}
