use super::auth_ping::AuthPingLog;

pub(crate) fn record_anthropic_oauth_readiness(
    readiness: kuzushi_openai::OauthReadiness,
    log: &mut AuthPingLog,
) -> bool {
    let (ok, message) = anthropic_oauth_readiness_message(readiness);
    log.record(ok, message);
    ok
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

pub(crate) fn record_anthropic_env_presence(log: &mut AuthPingLog) -> bool {
    let oauth_env = record_env_presence(
        log,
        &["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"],
        "ANTHROPIC_OAUTH_TOKEN/AUTH_TOKEN env present",
    );
    let api_key = record_env_presence(log, &["ANTHROPIC_API_KEY"], "ANTHROPIC_API_KEY env present");
    oauth_env || api_key
}

pub(crate) fn record_openai_runtime_auth_presence(log: &mut AuthPingLog) -> bool {
    let api_key = record_env_presence(log, &["OPENAI_API_KEY"], "OPENAI_API_KEY env present");
    record_openai_base_url_presence(log);
    let hosted = record_hosted_openai_presence(log);
    if !api_key && !hosted {
        log.record(false, openai_missing_credential_message());
    }
    api_key || hosted
}

fn record_openai_base_url_presence(log: &mut AuthPingLog) {
    if let Ok(base_url) = std::env::var("OPENAI_BASE_URL") {
        log.record(
            true,
            format!(
                "OPENAI_BASE_URL present ({}); runtime/provider auth may be injected out-of-band",
                masked_openai_base_url(base_url)
            ),
        );
    }
}

fn masked_openai_base_url(base_url: String) -> String {
    if base_url.len() <= 96 {
        return base_url;
    }
    format!("{}…", &base_url[..96])
}

fn record_hosted_openai_presence(log: &mut AuthPingLog) -> bool {
    if std::env::var("CODEX_CI").is_ok() {
        log.record(
            true,
            "hosted runtime flag present; OpenAI may authenticate without local oauth-credentials.json",
        );
        return true;
    }
    false
}

pub(crate) fn record_env_presence(log: &mut AuthPingLog, names: &[&str], label: &str) -> bool {
    if names.iter().any(|name| std::env::var(name).is_ok()) {
        log.record(true, label);
        return true;
    }
    false
}

pub(crate) fn anthropic_missing_credential_message() -> &'static str {
    "no Anthropic credentials found. Next: export ANTHROPIC_API_KEY=... or run `auth login anthropic` in the shell."
}

pub(crate) fn openai_missing_credential_message() -> &'static str {
    "OPENAI_API_KEY env missing. Next: export OPENAI_API_KEY=... before running `kuzushi auth ping openai`."
}

pub(crate) fn auth_ping_model(
    model_override: Option<String>,
    config: &kuzushi_core::V2Config,
) -> anyhow::Result<String> {
    kuzushi_core::runtime::resolve_explicit_model(
        "auth ping",
        model_override,
        config.model.as_deref(),
    )
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
