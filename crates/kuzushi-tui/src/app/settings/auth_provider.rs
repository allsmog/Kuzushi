//! Canonical auth-provider identity across shell scenes.
//!
//! OpenAI deliberately has different identifiers at different boundaries:
//! operators type `openai`, OAuth-backed models use `openai-codex`, and the
//! credential store also keys ChatGPT OAuth as `openai-codex`. Keeping those
//! projections on one enum prevents a model-scene identifier from leaking
//! into the auth command or bridge scene.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthProvider {
    OpenAi,
    Anthropic,
    GitHubCopilot,
}

impl AuthProvider {
    pub(crate) fn from_login_command(input: &str) -> Result<Self, String> {
        match normalized(input).as_str() {
            "" | "openai" => Ok(Self::OpenAi),
            "anthropic" | "claude" => Ok(Self::Anthropic),
            "github-copilot" | "copilot" => Ok(Self::GitHubCopilot),
            other => Err(unsupported_provider(other)),
        }
    }

    pub(crate) fn from_scene_provider(provider: &str) -> Option<Self> {
        match provider {
            "openai" | "openai-codex" => Some(Self::OpenAi),
            "anthropic" => Some(Self::Anthropic),
            "github-copilot" => Some(Self::GitHubCopilot),
            _ => None,
        }
    }

    pub(crate) fn login_command_name(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::GitHubCopilot => "github-copilot",
        }
    }

    pub(crate) fn oauth_model_provider(self) -> &'static str {
        match self {
            Self::OpenAi => "openai-codex",
            Self::Anthropic => "anthropic",
            Self::GitHubCopilot => "github-copilot",
        }
    }

    pub(crate) fn oauth_credential_key(self) -> &'static str {
        self.oauth_model_provider()
    }

    pub(crate) fn api_key_provider(self) -> &'static str {
        self.login_command_name()
    }

    pub(crate) fn missing_credential_guidance(self, model: &str, provider: &str) -> String {
        match self {
            Self::OpenAi => openai_credential_guidance(model, provider),
            Self::Anthropic => {
                format!("{model} requires ANTHROPIC_API_KEY or stored Anthropic OAuth")
            }
            Self::GitHubCopilot => {
                format!("{model} requires stored GitHub Copilot OAuth")
            }
        }
    }
}

fn openai_credential_guidance(model: &str, provider: &str) -> String {
    match provider {
        "openai" => format!(
            "{model} requires OPENAI_API_KEY; OpenAI OAuth is compatible with openai-codex models only"
        ),
        "openai-codex" => {
            format!("{model} requires stored OpenAI OAuth; run `auth login openai`")
        }
        _ => format!("{model} uses unsupported OpenAI provider namespace {provider:?}"),
    }
}

pub(crate) fn auth_provider_label(provider: &str) -> &str {
    AuthProvider::from_scene_provider(provider)
        .map(AuthProvider::login_command_name)
        .unwrap_or(provider)
}

fn normalized(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn unsupported_provider(provider: &str) -> String {
    format!(
        "unsupported auth login provider {provider:?}. Supported: openai, anthropic, github-copilot. Next: auth login openai browser"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_identity_is_explicit_for_each_scene() {
        let provider = AuthProvider::from_scene_provider("openai-codex").unwrap();

        assert_eq!(provider.login_command_name(), "openai");
        assert_eq!(provider.oauth_model_provider(), "openai-codex");
        assert_eq!(provider.oauth_credential_key(), "openai-codex");
        assert_eq!(provider.api_key_provider(), "openai");
        assert_eq!(auth_provider_label("openai-codex"), "openai");
    }

    #[test]
    fn public_login_parser_does_not_accept_internal_model_ids() {
        assert_eq!(
            AuthProvider::from_login_command("openai").unwrap(),
            AuthProvider::OpenAi
        );
        assert!(AuthProvider::from_login_command("openai-codex").is_err());
    }

    #[test]
    fn every_supported_provider_round_trips_through_the_login_scene() {
        for provider in [
            AuthProvider::OpenAi,
            AuthProvider::Anthropic,
            AuthProvider::GitHubCopilot,
        ] {
            assert_eq!(
                AuthProvider::from_login_command(provider.login_command_name()).unwrap(),
                provider
            );
        }
    }

    #[test]
    fn openai_guidance_distinguishes_api_key_and_oauth_model_namespaces() {
        let provider = AuthProvider::OpenAi;

        assert!(provider
            .missing_credential_guidance("openai:gpt-5.5", "openai")
            .contains("requires OPENAI_API_KEY"));
        assert!(provider
            .missing_credential_guidance("openai-codex:gpt-5.4", "openai-codex")
            .contains("requires stored OpenAI OAuth"));
    }
}
