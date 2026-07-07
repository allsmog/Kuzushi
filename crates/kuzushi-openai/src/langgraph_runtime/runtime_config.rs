use anyhow::Result;
use kuzushi_core::{RuntimeConfig, ScanCancellation, V2Config};
use std::path::Path;

use super::bridge_process::default_langgraph_bridge_command;

#[derive(Debug, Clone)]
pub struct LangGraphRuntime {
    pub(crate) command: Vec<String>,
    pub(crate) api_key_env: String,
    pub(crate) api_key: Option<String>,
    pub(crate) base_url: Option<String>,
    pub(crate) thinking_level: Option<String>,
    pub(crate) cancellation: Option<ScanCancellation>,
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
            cancellation: None,
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
