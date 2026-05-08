use super::*;

pub(crate) fn oauth_credentials_path() -> Option<PathBuf> {
    env::var_os("HOME").map(|home| PathBuf::from(home).join(".kuzushi/oauth-credentials.json"))
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
        "stored; value hidden".to_string()
    } else {
        "incomplete".to_string()
    }
}

pub(crate) fn thinking_level_from_input(input: &serde_json::Value) -> Option<String> {
    ["thinkingLevel", "reasoningEffort", "effort"]
        .iter()
        .find_map(|key| input.get(*key).and_then(serde_json::Value::as_str))
        .and_then(normalize_thinking_level)
        .map(ToString::to_string)
}
