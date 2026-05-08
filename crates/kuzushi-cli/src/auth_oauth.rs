use crate::auth_ping::AuthPingLog;

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

pub(crate) fn format_unix_ms(ms: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let when = UNIX_EPOCH + Duration::from_millis(ms);
    let now = SystemTime::now();
    let delta = match when.duration_since(now) {
        Ok(d) => format!("in {}s", d.as_secs()),
        Err(e) => format!("{}s ago", e.duration().as_secs()),
    };
    format!("{ms}ms unix; {delta}")
}
