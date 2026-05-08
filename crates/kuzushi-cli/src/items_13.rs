use super::prelude::*;
use super::*;

pub(crate) fn record_anthropic_oauth_readiness(
    readiness: kuzushi_openai::OauthReadiness,
    log: &mut AuthPingLog,
) {
    let (ok, message) = anthropic_oauth_readiness_message(readiness);
    log.record(ok, message);
}

pub(crate) fn anthropic_oauth_readiness_message(
    readiness: kuzushi_openai::OauthReadiness,
) -> (bool, String) {
    match readiness {
        kuzushi_openai::OauthReadiness::Ready { expires_at_ms } => (
            true,
            format!(
                "oauth credentials ready (expires {})",
                format_unix_ms(expires_at_ms)
            ),
        ),
        kuzushi_openai::OauthReadiness::Expired { expires_at_ms } => (
            true,
            format!(
                "oauth credentials present but expired ({}); will refresh on next call",
                format_unix_ms(expires_at_ms)
            ),
        ),
        kuzushi_openai::OauthReadiness::Missing { searched } => (
            false,
            format!("oauth credentials missing at {}", searched.display()),
        ),
        kuzushi_openai::OauthReadiness::Invalid { searched, reason } => (
            false,
            format!(
                "oauth credentials invalid at {}: {reason}",
                searched.display()
            ),
        ),
    }
}

pub(crate) fn record_anthropic_env_presence(log: &mut AuthPingLog) {
    record_env_presence(
        log,
        &["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"],
        "ANTHROPIC_OAUTH_TOKEN/AUTH_TOKEN env present",
    );
    record_env_presence(log, &["ANTHROPIC_API_KEY"], "ANTHROPIC_API_KEY env present");
}

pub(crate) fn record_env_presence(log: &mut AuthPingLog, names: &[&str], label: &str) {
    if names.iter().any(|name| std::env::var(name).is_ok()) {
        log.record(true, label);
    }
}

pub(crate) fn auth_ping_model(
    model_override: Option<String>,
    config: &kuzushi_core::V2Config,
) -> String {
    model_override
        .or_else(|| config.model.clone())
        .unwrap_or_else(|| "anthropic:claude-haiku-4-5".to_string())
}

pub(crate) fn auth_ping_bridge_command(config: &kuzushi_core::V2Config) -> Vec<String> {
    config
        .runtime
        .agent_bridge_command
        .clone()
        .unwrap_or_else(|| {
            vec![
                "node".to_string(),
                "scripts/pi-agent-core-bridge.mjs".to_string(),
            ]
        })
}

pub(crate) fn auth_ping_envelope(
    config: &kuzushi_core::V2Config,
    model: String,
) -> serde_json::Value {
    serde_json::json!({
        "type": "ping",
        "model": model,
        "apiKeyEnv": config.runtime.api_key_env,
        "apiKey": std::env::var(&config.runtime.api_key_env).ok(),
    })
}

pub(crate) fn run_auth_ping_bridge(
    bridge_command: &[String],
    envelope: &serde_json::Value,
    log: &mut AuthPingLog,
) -> Result<serde_json::Value> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(&bridge_command[0])
        .args(&bridge_command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("could not start bridge {}", bridge_command[0]))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("could not open bridge stdin")?;
        stdin.write_all(serde_json::to_vec(&envelope)?.as_slice())?;
    }
    let output = child
        .wait_with_output()
        .context("could not read bridge output")?;
    match parse_bridge_stdout(&output.stdout) {
        Ok(value) => Ok(value),
        Err(e) => {
            log.record(false, format!("bridge returned non-JSON output: {e}"));
            eprintln!("    stdout: {}", String::from_utf8_lossy(&output.stdout));
            eprintln!("    stderr: {}", String::from_utf8_lossy(&output.stderr));
            std::process::exit(1);
        }
    }
}
