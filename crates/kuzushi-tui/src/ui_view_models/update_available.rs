use super::{cost_model, format_session_cost};
use crate::{
    build_version, ShellApp, UpdateAvailableFooter, UpdateAvailableSnapshot, UpdateAvailableStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateAvailableModel {
    pub(crate) status: UpdateAvailableStatus,
    pub(crate) body_rows: Vec<String>,
    pub(crate) footer: UpdateAvailableFooter,
    pub(crate) release_available: bool,
}

pub(crate) fn update_available_model(app: &ShellApp) -> UpdateAvailableModel {
    app.update_available_snapshot()
        .cloned()
        .map(UpdateAvailableModel::from)
        .unwrap_or_else(|| default_update_available_model(app))
}

impl From<UpdateAvailableSnapshot> for UpdateAvailableModel {
    fn from(snapshot: UpdateAvailableSnapshot) -> Self {
        Self {
            status: snapshot.status,
            body_rows: snapshot.body_rows,
            footer: snapshot.footer,
            release_available: true,
        }
    }
}

fn default_update_available_model(app: &ShellApp) -> UpdateAvailableModel {
    UpdateAvailableModel {
        status: default_status(app),
        body_rows: default_body_rows(),
        footer: default_footer(app),
        release_available: false,
    }
}

fn default_status(app: &ShellApp) -> UpdateAvailableStatus {
    UpdateAvailableStatus {
        target: app
            .target()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
        ctx: "not built".to_string(),
        model: app
            .config()
            .model
            .clone()
            .unwrap_or_else(|| "unconfigured".to_string()),
        module: "update".to_string(),
        cost: default_cost(app),
    }
}

fn default_cost(app: &ShellApp) -> String {
    cost_model(app)
        .budget_status
        .map(|status| status.cells[1].clone())
        .unwrap_or_else(|| format_session_cost(0.0))
}

fn default_body_rows() -> Vec<String> {
    vec![
        "--:--:--  ·  update check · not running from this shell".to_string(),
        String::new(),
        " -- UPDATE -------------------------------------------------------------------------------------------------------------".to_string(),
        format!("current binary      {}", build_version()),
        "release feed        not configured in the Rust shell".to_string(),
        "next step           use the repository workflow outside the TUI to pull, test, and restart".to_string(),
        String::new(),
        " -- OPTIONS ------------------------------------------------------------------------------------------------------------".to_string(),
        "   /update             reopen this status screen".to_string(),
        "   /doctor             inspect local toolchain and optional binaries".to_string(),
        "   /config             inspect runtime configuration".to_string(),
    ]
}

fn default_footer(app: &ShellApp) -> UpdateAvailableFooter {
    UpdateAvailableFooter {
        stage: "update status".to_string(),
        findings: app.findings_total_count(),
        keybinds: vec![
            ("/update".to_string(), "status".to_string()),
            ("/doctor".to_string(), "preflight".to_string()),
            ("/config".to_string(), "config".to_string()),
        ],
        prompt_module: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn update_available_model_uses_route_owned_snapshot() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.replace_update_available_snapshot_for_test(Some(snapshot()));

        let model = update_available_model(&app);

        assert_eq!(model.status.module, "update-route");
        assert_eq!(model.body_rows, vec!["route body".to_string()]);
        assert_eq!(model.footer.prompt_module.as_deref(), Some("update"));
        assert!(model.release_available);
    }

    #[test]
    fn default_update_status_does_not_claim_release_availability() {
        let app = ShellApp::new(V2Config::default(), None);

        let model = update_available_model(&app);

        assert!(!model.release_available);
        assert!(model
            .body_rows
            .iter()
            .any(|row| row.contains("release feed") && row.contains("not configured")));
    }

    fn snapshot() -> UpdateAvailableSnapshot {
        UpdateAvailableSnapshot {
            status: UpdateAvailableStatus {
                target: "target".to_string(),
                ctx: "ctx".to_string(),
                model: "model".to_string(),
                module: "update-route".to_string(),
                cost: "$0.00".to_string(),
            },
            body_rows: vec!["route body".to_string()],
            footer: UpdateAvailableFooter {
                stage: "update".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: Some("update".to_string()),
            },
        }
    }
}
