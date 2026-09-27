//! Credential-entry row model for the auth-method picker.
//!
//! The picker surface is generalized into an ordered list of rows so the
//! route state and the renderer agree on selection semantics by *identity*
//! (`AuthMethodRowKind`) rather than a hardcoded cursor index. This keeps the
//! "offline demo" escape hatch a first-class row that can be promoted in the
//! layout without silently desyncing which action a given cursor position
//! triggers.

use crate::app::settings::AuthProvider;

/// The kind of credential action a picker row performs. Selection is matched
/// on this identity, never on the row's numeric position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethodRowKind {
    /// Paste an API key for this session (hidden, session-only).
    ApiKey,
    /// Dispatch the provider's OAuth login flow.
    OAuth,
    /// Run the bundled offline fixture — no key, model, or scanner binary.
    OfflineDemo,
}

/// A single displayable credential-entry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthMethodRow {
    pub kind: AuthMethodRowKind,
    pub label: &'static str,
    pub hint: &'static str,
}

const OFFLINE_DEMO_ROW: AuthMethodRow = AuthMethodRow {
    kind: AuthMethodRowKind::OfflineDemo,
    label: "Offline demo",
    hint: "run bundled offline fixture now; no key, model, or scanner binary",
};

const ANTHROPIC_AUTH_ROWS: [AuthMethodRow; 3] = [
    AuthMethodRow {
        kind: AuthMethodRowKind::ApiKey,
        label: "API key (ANTHROPIC_API_KEY)",
        hint: "paste key here, Enter accepts for this session",
    },
    AuthMethodRow {
        kind: AuthMethodRowKind::OAuth,
        label: "Claude.ai OAuth login",
        hint: "opens a browser flow (or headless link in non-TTY)",
    },
    OFFLINE_DEMO_ROW,
];

const OPENAI_API_AUTH_ROWS: [AuthMethodRow; 3] = [
    AuthMethodRow {
        kind: AuthMethodRowKind::ApiKey,
        label: "API key (OPENAI_API_KEY)",
        hint: "paste key here, Enter accepts for this session",
    },
    AuthMethodRow {
        kind: AuthMethodRowKind::OAuth,
        label: "Use OpenAI OAuth (switch model)",
        hint: "reuse or sign in; asks before switching the model",
    },
    OFFLINE_DEMO_ROW,
];

const OPENAI_OAUTH_AUTH_ROWS: [AuthMethodRow; 2] = [
    AuthMethodRow {
        kind: AuthMethodRowKind::OAuth,
        label: "OpenAI OAuth login",
        hint: "opens a browser flow (or headless link in non-TTY)",
    },
    OFFLINE_DEMO_ROW,
];

/// Ordered credential-entry rows for a provider. Every credentialed provider
/// offers the offline demo as a keyless escape hatch, so it is always the
/// last row. OpenAI API models keep their API-key requirement, but also expose
/// an explicit switch to an OAuth-compatible model so a stored connection is
/// reachable without pretending it authenticates the current API model.
pub fn auth_method_rows(provider: &str) -> Vec<AuthMethodRow> {
    match provider {
        "anthropic" => ANTHROPIC_AUTH_ROWS.to_vec(),
        "openai" => OPENAI_API_AUTH_ROWS.to_vec(),
        "openai-codex" => OPENAI_OAUTH_AUTH_ROWS.to_vec(),
        _ => match AuthProvider::from_scene_provider(provider) {
            Some(AuthProvider::GitHubCopilot) | None => Vec::new(),
            Some(AuthProvider::Anthropic | AuthProvider::OpenAi) => unreachable!(),
        },
    }
}

pub fn credential_recovery_rows(provider: &str) -> Vec<AuthMethodRow> {
    auth_method_rows(provider)
        .into_iter()
        .filter(|row| row.kind != AuthMethodRowKind::OfflineDemo)
        .collect()
}

/// Just the ordered row kinds — consumed by the picker route state so it can
/// resolve the selected row's identity without owning the renderer's labels.
pub fn auth_method_row_kinds(provider: &str) -> Vec<AuthMethodRowKind> {
    auth_method_rows(provider)
        .iter()
        .map(|row| row.kind)
        .collect()
}

pub fn credential_recovery_row_kinds(provider: &str) -> Vec<AuthMethodRowKind> {
    credential_recovery_rows(provider)
        .iter()
        .map(|row| row.kind)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_credential_screens_end_with_the_offline_demo_row() {
        for provider in ["anthropic", "openai", "openai-codex"] {
            let rows = auth_method_rows(provider);
            assert_eq!(
                rows.last().map(|row| row.kind),
                Some(AuthMethodRowKind::OfflineDemo)
            );
        }
    }

    #[test]
    fn openai_namespaces_offer_only_compatible_credentials() {
        assert_eq!(
            auth_method_row_kinds("openai"),
            vec![
                AuthMethodRowKind::ApiKey,
                AuthMethodRowKind::OAuth,
                AuthMethodRowKind::OfflineDemo,
            ]
        );
        assert_eq!(
            auth_method_row_kinds("openai-codex"),
            vec![AuthMethodRowKind::OAuth, AuthMethodRowKind::OfflineDemo]
        );
        assert_eq!(
            credential_recovery_row_kinds("openai"),
            vec![AuthMethodRowKind::ApiKey, AuthMethodRowKind::OAuth]
        );
    }

    #[test]
    fn unknown_provider_has_no_credential_rows() {
        assert!(auth_method_rows("local").is_empty());
        assert!(auth_method_row_kinds("local").is_empty());
    }

    #[test]
    fn row_kinds_track_the_row_order() {
        assert_eq!(
            auth_method_row_kinds("anthropic"),
            vec![
                AuthMethodRowKind::ApiKey,
                AuthMethodRowKind::OAuth,
                AuthMethodRowKind::OfflineDemo,
            ]
        );
    }
}
