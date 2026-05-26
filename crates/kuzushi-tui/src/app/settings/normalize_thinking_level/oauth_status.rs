use super::*;

pub(crate) fn oauth_credentials_path() -> Option<PathBuf> {
    env::var_os("HOME").map(kuzushi_core::config::default_oauth_credentials_path)
}

pub(crate) fn oauth_provider_status(provider: &str) -> String {
    let Some(path) = oauth_credentials_path() else {
        return "missing".to_string();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return "missing".to_string();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return "unreadable".to_string();
    };
    let Some(entry) = json.get(provider) else {
        return "missing".to_string();
    };
    if entry
        .get("access")
        .and_then(serde_json::Value::as_str)
        .is_some()
        && entry
            .get("refresh")
            .and_then(serde_json::Value::as_str)
            .is_some()
    {
        if let Some(expires) = entry.get("expires").and_then(serde_json::Value::as_u64) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0);
            if expires <= now {
                return "expired; will refresh on next call".to_string();
            }
        }
        "stored; value hidden".to_string()
    } else {
        "incomplete".to_string()
    }
}

pub(crate) fn oauth_credentials_path_display() -> String {
    oauth_credentials_path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(default_oauth_credentials_path_display)
}

pub(crate) fn default_oauth_credentials_path_display() -> String {
    format!(
        "~/.kuzushi/{}",
        kuzushi_core::config::OAUTH_CREDENTIALS_FILE
    )
}

pub(crate) fn thinking_level_from_input(input: &serde_json::Value) -> Option<String> {
    ["thinkingLevel", "reasoningEffort", "effort"]
        .iter()
        .find_map(|key| input.get(*key).and_then(serde_json::Value::as_str))
        .and_then(normalize_thinking_level)
        .map(ToString::to_string)
}
