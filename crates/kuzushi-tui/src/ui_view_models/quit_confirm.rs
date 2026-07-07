use super::{cost_model, format_session_cost};
use crate::{
    QuitConfirmFooter, QuitConfirmSection, QuitConfirmSnapshot, QuitConfirmStatus, ShellApp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuitConfirmModel {
    pub(crate) status: QuitConfirmStatus,
    pub(crate) timestamp: String,
    pub(crate) warning_title: String,
    pub(crate) warning_body: String,
    pub(crate) sections: Vec<QuitConfirmSection>,
    pub(crate) default_line: String,
    pub(crate) footer: QuitConfirmFooter,
}

pub(crate) fn quit_confirm_model(app: &ShellApp) -> QuitConfirmModel {
    app.quit_confirm_snapshot()
        .cloned()
        .map(QuitConfirmModel::from)
        .unwrap_or_else(|| default_quit_confirm_model(app))
}

impl From<QuitConfirmSnapshot> for QuitConfirmModel {
    fn from(snapshot: QuitConfirmSnapshot) -> Self {
        Self {
            status: snapshot.status,
            timestamp: snapshot.timestamp,
            warning_title: snapshot.warning_title,
            warning_body: snapshot.warning_body,
            sections: snapshot.sections,
            default_line: snapshot.default_line,
            footer: snapshot.footer,
        }
    }
}

fn default_quit_confirm_model(app: &ShellApp) -> QuitConfirmModel {
    let active_count = usize::from(app.has_running_work());
    QuitConfirmModel {
        status: default_status(app),
        timestamp: "--:--:--".to_string(),
        warning_title: "CONFIRM SESSION EXIT".to_string(),
        warning_body: default_warning(active_count),
        sections: default_sections(active_count),
        default_line: "default · n · cancel".to_string(),
        footer: default_footer(app, active_count),
    }
}

fn default_warning(active_count: usize) -> String {
    if active_count > 0 {
        "active work may stop if you exit without detaching".to_string()
    } else {
        "no active job is running; the session can be checkpointed before exit".to_string()
    }
}

fn default_status(app: &ShellApp) -> QuitConfirmStatus {
    QuitConfirmStatus {
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
        module: "quit".to_string(),
        cost: default_cost(app),
    }
}

fn default_cost(app: &ShellApp) -> String {
    cost_model(app)
        .budget_status
        .map(|status| status.cells[1].clone())
        .unwrap_or_else(|| format_session_cost(0.0))
}

fn default_sections(active_count: usize) -> Vec<QuitConfirmSection> {
    vec![
        QuitConfirmSection::new(
            "IN FLIGHT · will be checkpointed if you confirm",
            default_in_flight_rows(active_count),
        ),
        QuitConfirmSection::new(
            "CHOOSE",
            vec![
                "    Y   checkpoint all + /story + quit   write a story memo first".to_string(),
                "    y   checkpoint all + quit             resumable next session".to_string(),
                "    p   keep running in background         detach the TUI".to_string(),
                "    n   cancel                            stay here".to_string(),
            ],
        ),
    ]
}

fn default_in_flight_rows(active_count: usize) -> Vec<String> {
    if active_count > 0 {
        vec!["    ⏵   active worker   running · detach to keep it alive".to_string()]
    } else {
        vec!["    ·   no active module runs".to_string()]
    }
}

fn default_footer(app: &ShellApp, active_count: usize) -> QuitConfirmFooter {
    QuitConfirmFooter {
        stage: format!("quit · {active_count} in flight"),
        findings: app.findings_total_count(),
        keybinds: vec![
            ("Y".to_string(), "checkpoint+story+quit".to_string()),
            ("y".to_string(), "checkpoint+quit".to_string()),
            ("p".to_string(), "detach".to_string()),
            ("n".to_string(), "cancel".to_string()),
        ],
        prompt_module: "quit".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn quit_confirm_model_uses_route_owned_snapshot() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.replace_quit_confirm_snapshot_for_test(Some(QuitConfirmSnapshot {
            status: QuitConfirmStatus {
                target: "target".to_string(),
                ctx: "ctx".to_string(),
                model: "model".to_string(),
                module: "quit".to_string(),
                cost: "$0.00".to_string(),
            },
            timestamp: "12:00:00".to_string(),
            warning_title: "ROUTE SNAPSHOT".to_string(),
            warning_body: "body".to_string(),
            sections: vec![QuitConfirmSection::new("SECTION", vec!["row".to_string()])],
            default_line: "default".to_string(),
            footer: QuitConfirmFooter {
                stage: "quit".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: "quit".to_string(),
            },
        }));

        let model = quit_confirm_model(&app);

        assert_eq!(model.warning_title, "ROUTE SNAPSHOT");
        assert_eq!(model.sections.len(), 1);
        assert_eq!(model.footer.prompt_module, "quit");
    }
}
