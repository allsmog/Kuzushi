use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn has_env_token() -> bool {
    ["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"]
        .iter()
        .any(|name| {
            std::env::var(name)
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
        })
}
