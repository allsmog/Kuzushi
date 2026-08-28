//! Provider-bound model/credential binding.
//!
//! Every surface that builds a provider request — execution or diagnostic —
//! must resolve which public authentication provider a model belongs to and
//! which credential environment variable *name* carries that provider's
//! secret. Binding those two facts in one place keeps a credential from
//! crossing a provider trust boundary.
//!
//! This module is pure policy: it never reads the environment, the
//! filesystem, or a process, and it carries credential env **names**, never
//! credential values.

use anyhow::Result;

use super::no_silent_fallback::{bridge_api_key_env_for_model, canonical_model_spec};

/// The public provider an operator names on an auth surface.
///
/// Several model-provider namespaces share one public provider: Claude on
/// Vertex is still Anthropic, and the OAuth-backed Codex transport is still
/// OpenAI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicAuthProvider {
    Anthropic,
    OpenAi,
}

impl PublicAuthProvider {
    pub fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }
}

/// A model bound to the credential that may legitimately authenticate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelAuthBinding {
    /// Canonical `provider:model-id` spec.
    pub model: String,
    /// Model-provider namespace, such as `openai-codex` or `vertex-anthropic`.
    pub model_provider: String,
    /// Public provider an operator would name on an auth surface.
    pub public_provider: PublicAuthProvider,
    /// Credential environment variable **name**. Never a credential value.
    pub api_key_env: String,
}

/// Map a model-provider namespace onto its public authentication provider.
pub fn public_auth_provider(model_provider: &str) -> Result<PublicAuthProvider> {
    match model_provider.trim() {
        "anthropic" | "vertex-anthropic" => Ok(PublicAuthProvider::Anthropic),
        "openai" | "openai-codex" => Ok(PublicAuthProvider::OpenAi),
        other => anyhow::bail!(
            "model provider {other:?} has no public authentication provider; use anthropic:*, vertex-anthropic:*, openai:*, or openai-codex:*"
        ),
    }
}

/// Bind a model to its provider credential env name, reusing the shared
/// no-silent-fallback rule rather than restating it.
pub fn bind_model_auth(model: &str, api_key_env: &str) -> Result<ModelAuthBinding> {
    let model = canonical_model_spec(model)?;
    let api_key_env = bridge_api_key_env_for_model(&model, api_key_env)?;
    let model_provider = provider_namespace(&model).to_string();
    let public_provider = public_auth_provider(&model_provider)?;
    Ok(ModelAuthBinding {
        model,
        model_provider,
        public_provider,
        api_key_env,
    })
}

/// Bind a model to its credential and refuse when the operator asked for a
/// different public provider than the model authenticates with.
pub fn require_model_auth_binding(
    requested: PublicAuthProvider,
    model: &str,
    api_key_env: &str,
) -> Result<ModelAuthBinding> {
    let binding = bind_model_auth(model, api_key_env)?;
    if binding.public_provider != requested {
        anyhow::bail!(
            "requested {} authentication, but model {} authenticates with {}; Kuzushi will not forward a credential across providers",
            requested.label(),
            binding.model,
            binding.public_provider.label()
        );
    }
    Ok(binding)
}

fn provider_namespace(canonical_model: &str) -> &str {
    canonical_model
        .split_once(':')
        .map(|(provider, _)| provider)
        .unwrap_or(canonical_model)
}
