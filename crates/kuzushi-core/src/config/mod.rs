/// Declarative hint that the operator expects Anthropic OAuth as the
/// credential source for `anthropic:*` models.
///
/// The bridge (`scripts/langgraph-bridge.mjs`) is the actual refresh
/// authority — it loads `oauth-credentials.json`, refreshes via
/// the LangGraph bridge, and forwards the access token. This Rust
/// struct exists so:
///
/// * `validate_config` can fail fast at startup if the operator declared
///   OAuth but the credentials file is missing or unreadable, instead of
///   waiting for the first LLM call.
/// * The TUI / CLI can describe the configured auth source without
///   round-tripping the bridge.
///
/// **No secret data is ever stored in this struct.** It only carries a
/// path and toggle flags. Tokens live in the file and the bridge process.
use anyhow::{Context, Result};
pub(crate) use apply_env_overrides::*;
pub(crate) use config_model::*;
pub(crate) use load_config_for_target::*;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
pub mod application;
mod apply_env_overrides;
mod config_file_io;
mod config_hash;
mod config_model;
pub mod domain;
mod load_config_for_target;
#[cfg(test)]
mod tests;

pub use config_hash::config_hash;
pub use config_model::default_oauth_credentials_path;
pub use config_model::AnthropicOauthConfig;
pub use config_model::ConfigPaths;
pub use config_model::FuzzExecutorConfig;
pub use config_model::GuidedPhase;
pub use config_model::GuidedPhaseConfig;
pub use config_model::KeybindingOverrideConfig;
pub use config_model::McpMountConfig;
pub use config_model::McpMountToolConfig;
pub use config_model::PhaseTemplateConfig;
pub use config_model::ReviewYieldConfig;
pub use config_model::ReviewYieldMode;
pub use config_model::RuntimeConfig;
pub use config_model::RuntimeKind;
pub use config_model::V2Config;
pub use config_model::DEFAULT_SESSION_RETENTION_DAYS;
pub use config_model::DEFAULT_WORKER_WATCHDOG_TIMEOUT_MS;
pub use config_model::OAUTH_CREDENTIALS_FILE;
pub use load_config_for_target::load_anthropic_oauth_config;
pub use load_config_for_target::load_config;
pub use load_config_for_target::load_config_for_target;
pub use load_config_for_target::load_config_for_target_with_diagnostics;
pub use load_config_for_target::load_config_with_diagnostics;
pub use load_config_for_target::persist_global_model_selection;
pub use load_config_for_target::write_default_config;
pub use load_config_for_target::ConfigDiagnostic;
pub use load_config_for_target::LoadedConfig;
