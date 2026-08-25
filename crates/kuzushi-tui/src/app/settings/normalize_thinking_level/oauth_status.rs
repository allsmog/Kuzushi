use super::*;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OauthCredentialStatus {
    Ready,
    Refreshable,
    Environment,
    Missing,
    Invalid,
}

impl OauthCredentialStatus {
    pub(crate) fn is_usable(self) -> bool {
        matches!(self, Self::Ready | Self::Refreshable | Self::Environment)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ready => "stored; value hidden",
            Self::Refreshable => "refreshable; refresh on next call",
            Self::Environment => "environment token; value hidden",
            Self::Missing => "missing",
            Self::Invalid => "invalid",
        }
    }
}

pub(crate) fn env_credential_is_ready(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

pub(crate) fn oauth_credentials_path(config: &V2Config) -> Option<PathBuf> {
    let oauth = config.runtime.anthropic_oauth.clone().unwrap_or_default();
    kuzushi_openai::resolve_oauth_credentials_path(&oauth).ok()
}

pub(crate) fn oauth_provider_status(config: &V2Config, provider: &str) -> OauthCredentialStatus {
    let Some(path) = oauth_credentials_path(config) else {
        return OauthCredentialStatus::Invalid;
    };
    let stored = match provider {
        "openai-codex" => canonical_status(kuzushi_openai::probe_openai_oauth_path(&path)),
        "anthropic" => canonical_status(kuzushi_openai::probe_anthropic_oauth(
            &config.runtime.anthropic_oauth.clone().unwrap_or_default(),
        )),
        _ => generic_provider_status(&path, provider),
    };
    if !stored.is_usable() && anthropic_env_oauth_is_ready(config, provider) {
        return OauthCredentialStatus::Environment;
    }
    stored
}

pub(crate) fn oauth_credential_is_ready(config: &V2Config, provider: &str) -> bool {
    oauth_provider_status(config, provider).is_usable()
}

fn anthropic_env_oauth_is_ready(config: &V2Config, provider: &str) -> bool {
    provider == "anthropic"
        && config
            .runtime
            .anthropic_oauth
            .as_ref()
            .is_some_and(|oauth| oauth.allow_env_token && kuzushi_openai::oauth::has_env_token())
}

pub(crate) fn oauth_provider_revision(config: &V2Config, provider: &str) -> Option<u64> {
    let path = oauth_credentials_path(config)?;
    let raw = fs::read_to_string(path).ok()?;
    let json = serde_json::from_str::<serde_json::Value>(&raw).ok()?;
    let entry = json.get(provider)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    entry.to_string().hash(&mut hasher);
    Some(hasher.finish())
}

fn canonical_status(
    readiness: anyhow::Result<kuzushi_openai::OauthReadiness>,
) -> OauthCredentialStatus {
    match readiness {
        Ok(kuzushi_openai::OauthReadiness::Ready { .. }) => OauthCredentialStatus::Ready,
        Ok(kuzushi_openai::OauthReadiness::Expired { .. }) => OauthCredentialStatus::Refreshable,
        Ok(kuzushi_openai::OauthReadiness::Missing { .. }) => OauthCredentialStatus::Missing,
        Ok(kuzushi_openai::OauthReadiness::Invalid { .. }) | Err(_) => {
            OauthCredentialStatus::Invalid
        }
    }
}

fn generic_provider_status(path: &std::path::Path, provider: &str) -> OauthCredentialStatus {
    let Ok(raw) = fs::read_to_string(path) else {
        return OauthCredentialStatus::Missing;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return OauthCredentialStatus::Invalid;
    };
    json.get(provider)
        .map(generic_entry_status)
        .unwrap_or(OauthCredentialStatus::Missing)
}

fn generic_entry_status(entry: &serde_json::Value) -> OauthCredentialStatus {
    if !non_empty_field(entry, "access") {
        return OauthCredentialStatus::Invalid;
    }
    let expired = entry
        .get("expires")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|expires| expires <= current_unix_ms());
    match (expired, non_empty_field(entry, "refresh")) {
        (true, true) => OauthCredentialStatus::Refreshable,
        (true, false) => OauthCredentialStatus::Invalid,
        (false, _) => OauthCredentialStatus::Ready,
    }
}

fn non_empty_field(entry: &serde_json::Value, field: &str) -> bool {
    entry
        .get(field)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.is_empty())
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn oauth_credentials_path_display(config: &V2Config) -> String {
    oauth_credentials_path(config)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_path_and_refreshable_runtime_semantics_are_shared() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("operator-oauth.json");
        fs::write(
            &path,
            r#"{"openai-codex":{"access":"secret","refresh":"refresh","expires":1}}"#,
        )
        .unwrap();
        let mut config = V2Config::default();
        config.runtime.anthropic_oauth = Some(kuzushi_core::AnthropicOauthConfig {
            credentials_path: Some(path.clone()),
            allow_env_token: false,
        });

        assert_eq!(
            oauth_credentials_path(&config).as_deref(),
            Some(path.as_path())
        );
        assert_eq!(
            oauth_provider_status(&config, "openai-codex"),
            OauthCredentialStatus::Refreshable
        );
        assert!(oauth_provider_status(&config, "openai-codex").is_usable());
    }

    #[test]
    fn access_only_and_malformed_entries_match_runtime_readiness() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("operator-oauth.json");
        let mut config = V2Config::default();
        config.runtime.anthropic_oauth = Some(kuzushi_core::AnthropicOauthConfig {
            credentials_path: Some(path.clone()),
            allow_env_token: false,
        });
        fs::write(
            &path,
            r#"{"openai-codex":{"access":"secret","expires":4102444800000}}"#,
        )
        .unwrap();

        assert_eq!(
            oauth_provider_status(&config, "openai-codex"),
            OauthCredentialStatus::Ready
        );

        fs::write(&path, r#"{"openai-codex":{"refresh":"secret"}}"#).unwrap();
        assert_eq!(
            oauth_provider_status(&config, "openai-codex"),
            OauthCredentialStatus::Invalid
        );
    }
}
