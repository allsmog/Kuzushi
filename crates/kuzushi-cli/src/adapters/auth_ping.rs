use super::auth_bridge::{bridge_ping_error, bridge_ping_summary};
use super::auth_oauth::{
    anthropic_missing_credential_message, auth_ping_model, record_anthropic_env_presence,
    record_anthropic_oauth_readiness, record_openai_runtime_auth_presence,
};
use crate::command::AuthCommand;
use anyhow::Result;
use kuzushi_core::runtime::{require_model_auth_binding, PublicAuthProvider};
use kuzushi_core::WorkspaceTarget;
use std::path::{Path, PathBuf};

pub(crate) fn auth_command(command: AuthCommand, target: Option<PathBuf>) -> Result<()> {
    match command {
        AuthCommand::Ping { provider, model } => auth_ping(&provider, model, target),
    }
}

pub(crate) fn auth_ping(
    provider: &str,
    model_override: Option<String>,
    target: Option<PathBuf>,
) -> Result<()> {
    let workspace = auth_ping_workspace(target)?;
    let config = auth_ping_config(workspace.as_ref())?;
    let source_root = auth_ping_source_root(workspace.as_ref());
    let mut log = AuthPingLog::default();
    run_auth_ping_checks(provider, model_override, &config, &source_root, &mut log)
}

pub(crate) fn auth_ping_workspace(target: Option<PathBuf>) -> Result<Option<WorkspaceTarget>> {
    target.as_deref().map(WorkspaceTarget::new).transpose()
}

pub(crate) fn auth_ping_config(
    workspace: Option<&WorkspaceTarget>,
) -> Result<kuzushi_core::V2Config> {
    crate::application::config_diagnostics::load_cli_config(workspace.map(WorkspaceTarget::root))
}

/// Root the default bridge command resolves against: the explicit target when
/// one was given, otherwise the working directory, as before.
fn auth_ping_source_root(workspace: Option<&WorkspaceTarget>) -> PathBuf {
    workspace
        .map(|workspace| workspace.root().to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

pub(crate) fn run_auth_ping_checks(
    provider: &str,
    model_override: Option<String>,
    config: &kuzushi_core::V2Config,
    source_root: &Path,
    log: &mut AuthPingLog,
) -> Result<()> {
    let provider = auth_ping_provider_kind(provider)?;
    eprintln!("[auth ping] provider = {}", provider.label());
    let model = auth_ping_model(model_override, config)?;
    log.record(true, format!("ping model = {model}"));
    // Bind the credential to the model's provider before anything reads an
    // environment variable or spawns a bridge. A disagreement must fail here,
    // never by sending one provider's secret to another.
    let binding = require_model_auth_binding(provider, &model, &config.runtime.api_key_env)?;
    probe_auth_credentials(provider, &binding.model, config, log)?;
    let parsed = auth_ping_round_trip(config, source_root, &binding.model)?;
    record_auth_ping_result(&parsed, log);
    log.exit_if_failed();
    eprintln!("\x1b[32mauth ping: OK\x1b[0m");
    Ok(())
}

fn auth_ping_round_trip(
    config: &kuzushi_core::V2Config,
    source_root: &Path,
    model: &str,
) -> Result<kuzushi_openai::PingBridgeResponse> {
    kuzushi_openai::LangGraphRuntime::from_config(config, source_root)?.auth_ping_blocking(model)
}

pub(crate) fn record_auth_ping_result(
    parsed: &kuzushi_openai::PingBridgeResponse,
    log: &mut AuthPingLog,
) {
    if let Some(error) = bridge_ping_error(parsed) {
        log.record(false, format!("bridge ping failed: {error}"));
        crate::application::config_diagnostics::exit_after_runtime_diagnostics(1);
    }
    log.record(true, bridge_ping_summary(parsed));
}

pub(crate) struct AuthPingLog {
    pub(crate) all_ok: bool,
}

impl Default for AuthPingLog {
    fn default() -> Self {
        Self { all_ok: true }
    }
}

impl AuthPingLog {
    pub(crate) fn record(&mut self, ok: bool, msg: impl Into<String>) {
        let msg = msg.into();
        if ok {
            eprintln!("  \x1b[32m✓\x1b[0m {msg}");
        } else {
            eprintln!("  \x1b[31m✗\x1b[0m {msg}");
            self.all_ok = false;
        }
    }

    pub(crate) fn exit_if_failed(&self) {
        if !self.all_ok {
            crate::application::config_diagnostics::exit_after_runtime_diagnostics(1);
        }
    }
}

pub(crate) fn probe_auth_credentials(
    provider: PublicAuthProvider,
    model: &str,
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Result<()> {
    if matches!(provider, PublicAuthProvider::Anthropic) {
        return probe_anthropic_credentials(config, log);
    }
    record_openai_auth_if_needed(provider, model, config, log)?;
    Ok(())
}

fn record_openai_auth_if_needed(
    provider: PublicAuthProvider,
    model: &str,
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Result<()> {
    if !matches!(provider, PublicAuthProvider::OpenAi) {
        return Ok(());
    }
    if model.trim().starts_with("openai-codex:") {
        return probe_openai_oauth_credentials(config, log);
    }
    record_openai_runtime_auth_presence(log);
    Ok(())
}

fn probe_openai_oauth_credentials(
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Result<()> {
    let oauth = config.runtime.anthropic_oauth.clone().unwrap_or_default();
    let path = kuzushi_openai::resolve_oauth_credentials_path(&oauth)?;
    let readiness = kuzushi_openai::probe_openai_oauth_path(&path)?;
    record_anthropic_oauth_readiness(readiness, log);
    Ok(())
}

pub(crate) fn auth_ping_provider_kind(provider: &str) -> Result<PublicAuthProvider> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "anthropic" => Ok(PublicAuthProvider::Anthropic),
        "openai" => Ok(PublicAuthProvider::OpenAi),
        other => {
            anyhow::bail!("unsupported auth ping provider {other:?}. Supported: openai, anthropic")
        }
    }
}

pub(crate) fn probe_anthropic_credentials(
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Result<()> {
    let oauth_ready = if let Some(oauth_cfg) = &config.runtime.anthropic_oauth {
        let readiness = kuzushi_openai::probe_anthropic_oauth(oauth_cfg)?;
        record_anthropic_oauth_readiness(readiness, log)
    } else {
        log.record(true, "oauth not configured; will check env / api key");
        false
    };
    let env_ready = record_anthropic_env_presence(log);
    if !oauth_ready && !env_ready {
        log.record(false, anthropic_missing_credential_message());
    }
    Ok(())
}
