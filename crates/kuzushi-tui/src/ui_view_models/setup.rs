use crate::app::{auth_ready_for_provider, oauth_provider_status, SetupRowId};
use crate::ShellApp;

mod readiness_rows;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialReadiness {
    ApiKey,
    StoredOAuth,
    Session,
    Missing,
    NotRequired,
}

impl CredentialReadiness {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "API key ready",
            Self::StoredOAuth => "stored OAuth ready",
            Self::Session => "session credential ready",
            Self::Missing => "credentials required",
            Self::NotRequired => "not required by this plan",
        }
    }

    fn is_ready(self) -> bool {
        !matches!(self, Self::Missing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetupReadinessTone {
    Ready,
    Optional,
    Blocked,
    Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupReadinessRow {
    pub(crate) id: SetupRowId,
    pub(crate) label: &'static str,
    pub(crate) status: String,
    pub(crate) detail: String,
    pub(crate) tone: SetupReadinessTone,
    pub(crate) blocker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupReadinessModel {
    pub(crate) rows: Vec<SetupReadinessRow>,
    pub(crate) first_blocker: Option<usize>,
    pub(crate) can_start: bool,
    pub(crate) selected_tasks: usize,
    pub(crate) selected_model_tasks: usize,
    pub(crate) credential_readiness: CredentialReadiness,
}

pub(crate) fn setup_readiness_model(app: &ShellApp) -> SetupReadinessModel {
    let selected_rows = selected_setup_rows(app);
    let selected_model_tasks = selected_rows.iter().filter(|row| row.model_backed).count();
    let credential_readiness = credential_readiness(app, selected_model_tasks > 0);
    let mut rows = readiness_rows::readiness_rows(
        app,
        &selected_rows,
        selected_model_tasks,
        credential_readiness,
    );
    let first_blocker = rows.iter().position(|row| row.blocker.is_some());
    let can_start = first_blocker.is_none();
    rows.push(start_row(&rows, first_blocker));
    SetupReadinessModel {
        rows,
        first_blocker,
        can_start,
        selected_tasks: selected_rows.len(),
        selected_model_tasks,
        credential_readiness,
    }
}

fn selected_setup_rows(app: &ShellApp) -> Vec<&crate::app::PlanningTaskRow> {
    let selected = app.engagement.planning_picker().selected();
    app.engagement
        .planning_picker()
        .tasks()
        .iter()
        .filter(|row| selected.contains(&row.id))
        .collect()
}

fn start_row(rows: &[SetupReadinessRow], first_blocker: Option<usize>) -> SetupReadinessRow {
    let can_start = first_blocker.is_none();
    let detail = first_blocker
        .and_then(|index| rows.get(index))
        .and_then(|row| row.blocker.clone())
        .unwrap_or_else(|| "Commit this Map plan and open Run Focus".to_string());
    SetupReadinessRow {
        id: SetupRowId::Start,
        label: "Start Map",
        status: if can_start { "READY" } else { "BLOCKED" }.to_string(),
        tone: if can_start {
            SetupReadinessTone::Action
        } else {
            SetupReadinessTone::Blocked
        },
        blocker: (!can_start).then(|| "resolve the readiness rows above first".to_string()),
        detail,
    }
}

fn credential_readiness(app: &ShellApp, required: bool) -> CredentialReadiness {
    if !required {
        return CredentialReadiness::NotRequired;
    }
    let Some(provider) = app
        .config()
        .model
        .as_deref()
        .and_then(|model| model.split(':').next())
    else {
        return CredentialReadiness::Missing;
    };
    credential_readiness_for_provider(app, provider)
}

pub(crate) fn configured_model_credential_readiness(app: &ShellApp) -> CredentialReadiness {
    app.config()
        .model
        .as_deref()
        .and_then(|model| model.split(':').next())
        .map(|provider| credential_readiness_for_provider(app, provider))
        .unwrap_or(CredentialReadiness::NotRequired)
}

pub(crate) fn credential_readiness_for_provider(
    app: &ShellApp,
    provider: &str,
) -> CredentialReadiness {
    classify_credential_readiness(
        app.session().session_api_key_ready(provider),
        provider == "openai-codex" || oauth_provider_status(provider).starts_with("stored"),
        auth_ready_for_provider(provider),
    )
}

fn classify_credential_readiness(
    session_ready: bool,
    stored_oauth: bool,
    provider_ready: bool,
) -> CredentialReadiness {
    match (session_ready, stored_oauth, provider_ready) {
        (true, _, _) => CredentialReadiness::Session,
        (false, true, true) => CredentialReadiness::StoredOAuth,
        (false, false, true) => CredentialReadiness::ApiKey,
        _ => CredentialReadiness::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::PlanningTaskId;
    use kuzushi_core::{V2Config, WorkspaceTarget};

    fn app_with_target(config: V2Config) -> (tempfile::TempDir, ShellApp) {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("Cargo.toml"),
            "[package]\nname='fixture'\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(config, Some(&workspace));
        app.open_setup();
        (target, app)
    }

    #[test]
    fn deterministic_map_plan_does_not_require_model_or_credentials() {
        let (_target, app) = app_with_target(V2Config::default());
        let model = setup_readiness_model(&app);
        assert_eq!(model.selected_model_tasks, 0);
        assert!(model.can_start);
        assert_eq!(model.credential_readiness, CredentialReadiness::NotRequired);
    }

    #[test]
    fn model_backed_selection_requires_explicit_model() {
        let (_target, mut app) = app_with_target(V2Config::default());
        app.engagement
            .planning_picker_mut()
            .selected_mut()
            .insert(PlanningTaskId::BuildThreatModel);
        let model = setup_readiness_model(&app);
        assert!(!model.can_start);
        assert_eq!(model.first_blocker, Some(2));
    }

    #[test]
    fn model_backed_selection_rejects_an_unsupported_provider() {
        let mut config = V2Config::default();
        config.model = Some("unsupported:model".to_string());
        let (_target, mut app) = app_with_target(config);
        app.engagement
            .planning_picker_mut()
            .selected_mut()
            .insert(PlanningTaskId::BuildThreatModel);

        let model = setup_readiness_model(&app);

        assert!(!model.can_start);
        assert_eq!(model.rows[2].status, "INCOMPATIBLE");
    }

    #[test]
    fn credential_readiness_distinguishes_api_oauth_and_session_sources() {
        assert_eq!(
            classify_credential_readiness(false, false, true),
            CredentialReadiness::ApiKey
        );
        assert_eq!(
            classify_credential_readiness(false, true, true),
            CredentialReadiness::StoredOAuth
        );
        assert_eq!(
            classify_credential_readiness(true, false, false),
            CredentialReadiness::Session
        );
        assert_eq!(
            classify_credential_readiness(false, true, false),
            CredentialReadiness::Missing
        );
    }

    #[test]
    fn zero_budget_is_an_honest_blocker() {
        let (_target, mut app) = app_with_target(V2Config::default());
        app.session_mut().set_session_budget_usd(Some(0.0));
        let model = setup_readiness_model(&app);
        assert!(!model.can_start);
        assert!(model.rows[5].detail.contains("positive"));
    }
}
