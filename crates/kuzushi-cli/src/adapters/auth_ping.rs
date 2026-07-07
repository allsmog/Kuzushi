use super::auth_bridge::{
    auth_ping_bridge_command, auth_ping_envelope, bridge_ping_error, bridge_ping_summary,
    run_auth_ping_bridge,
};
use super::auth_oauth::{
    anthropic_missing_credential_message, auth_ping_model, record_anthropic_env_presence,
    record_anthropic_oauth_readiness, record_openai_runtime_auth_presence,
};
use crate::command::AuthCommand;
use anyhow::Result;
use kuzushi_core::{load_config_for_target, WorkspaceTarget};
use std::path::PathBuf;

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
    let mut log = AuthPingLog::default();
    run_auth_ping_checks(provider, model_override, &config, &mut log)
}

pub(crate) fn auth_ping_workspace(target: Option<PathBuf>) -> Result<Option<WorkspaceTarget>> {
    target.as_deref().map(WorkspaceTarget::new).transpose()
}

pub(crate) fn auth_ping_config(
    workspace: Option<&WorkspaceTarget>,
) -> Result<kuzushi_core::V2Config> {
    load_config_for_target(workspace.map(WorkspaceTarget::root))
}

pub(crate) fn run_auth_ping_checks(
    provider: &str,
    model_override: Option<String>,
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Result<()> {
    let provider = auth_ping_provider_kind(provider)?;
    eprintln!("[auth ping] provider = {}", provider.label());
    probe_auth_credentials(provider, config, log)?;

    let model = auth_ping_model(model_override, config)?;
    log.record(true, format!("ping model = {model}"));

    let bridge_command = required_auth_ping_bridge_command(config, log);
    let envelope = auth_ping_envelope(config, model);
    let parsed = run_auth_ping_bridge(&bridge_command, &envelope, log)?;
    record_auth_ping_result(&parsed, log);
    log.exit_if_failed();
    eprintln!("\x1b[32mauth ping: OK\x1b[0m");
    Ok(())
}

pub(crate) fn required_auth_ping_bridge_command(
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Vec<String> {
    let command = auth_ping_bridge_command(config);
    if command.is_empty() {
        log.record(false, "bridge command is empty");
        std::process::exit(1);
    }
    command
}

pub(crate) fn record_auth_ping_result(parsed: &serde_json::Value, log: &mut AuthPingLog) {
    if let Some(error) = bridge_ping_error(parsed) {
        log.record(false, format!("bridge ping failed: {error}"));
        std::process::exit(1);
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
            std::process::exit(1);
        }
    }
}

pub(crate) fn probe_auth_credentials(
    provider: AuthProviderKind,
    config: &kuzushi_core::V2Config,
    log: &mut AuthPingLog,
) -> Result<()> {
    if matches!(provider, AuthProviderKind::Anthropic) {
        return probe_anthropic_credentials(config, log);
    }
    record_openai_auth_if_needed(provider, log);
    Ok(())
}

fn record_openai_auth_if_needed(provider: AuthProviderKind, log: &mut AuthPingLog) {
    if matches!(provider, AuthProviderKind::OpenAi) {
        record_openai_runtime_auth_presence(log);
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AuthProviderKind {
    Anthropic,
    OpenAi,
}

impl AuthProviderKind {
    fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }
}

pub(crate) fn auth_ping_provider_kind(provider: &str) -> Result<AuthProviderKind> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "anthropic" => Ok(AuthProviderKind::Anthropic),
        "openai" => Ok(AuthProviderKind::OpenAi),
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
