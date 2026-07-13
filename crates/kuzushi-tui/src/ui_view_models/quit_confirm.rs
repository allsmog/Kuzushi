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
        default_line: "default · n/N/Esc · stay".to_string(),
        footer: default_footer(app, active_count),
    }
}

fn default_warning(active_count: usize) -> String {
    if active_count > 0 {
        "the shell will request active-work cancellation and cleanup before exiting".to_string()
    } else {
        "no active work is running; exiting will close the shell".to_string()
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
            default_in_flight_title(active_count),
            default_in_flight_rows(active_count),
        ),
        QuitConfirmSection::new("CHOOSE", default_choice_rows(active_count)),
    ]
}

fn default_in_flight_title(active_count: usize) -> &'static str {
    if active_count > 0 {
        "IN FLIGHT · cancellation requested before exit"
    } else {
        "IN FLIGHT"
    }
}

fn default_choice_rows(active_count: usize) -> Vec<String> {
    let exit_detail = if active_count > 0 {
        "cancel active work if needed, then exit"
    } else {
        "close the shell"
    };
    vec![
        format!("    y/Y       exit   {exit_detail}"),
        "    n/N/Esc   stay   keep this session open".to_string(),
    ]
}

fn default_in_flight_rows(active_count: usize) -> Vec<String> {
    if active_count > 0 {
        vec!["    ⏵   active work   running · cancellation requested on exit".to_string()]
    } else {
        vec!["    ·   no active work".to_string()]
    }
}

fn default_footer(app: &ShellApp, active_count: usize) -> QuitConfirmFooter {
    let (stage, exit_label) = if active_count > 0 {
        ("quit · active work running", "cancel if needed + exit")
    } else {
        ("quit · no active work", "exit")
    };
    QuitConfirmFooter {
        stage: stage.to_string(),
        findings: app.findings_total_count(),
        keybinds: vec![
            ("y/Y".to_string(), exit_label.to_string()),
            ("n/N/Esc".to_string(), "stay".to_string()),
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

    #[test]
    fn idle_quit_confirm_only_offers_exit_or_stay() {
        let app = ShellApp::new(V2Config::default(), None);

        let model = quit_confirm_model(&app);

        assert_eq!(
            model.warning_body,
            "no active work is running; exiting will close the shell"
        );
        assert_eq!(model.sections[0].title, "IN FLIGHT");
        assert_eq!(model.sections[1].rows, default_choice_rows(0));
        assert_eq!(
            model.footer.keybinds,
            vec![
                ("y/Y".to_string(), "exit".to_string()),
                ("n/N/Esc".to_string(), "stay".to_string()),
            ]
        );
        assert_no_unimplemented_quit_claims(&model);
    }

    #[test]
    fn active_quit_confirm_explains_cancel_then_exit() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_running_tool_for_test("semgrep:scan");

        let model = quit_confirm_model(&app);

        assert!(model
            .warning_body
            .contains("request active-work cancellation and cleanup"));
        assert_eq!(
            model.sections[0].title,
            "IN FLIGHT · cancellation requested before exit"
        );
        assert!(model.sections[1].rows[0].contains("cancel active work if needed, then exit"));
        assert_eq!(
            model.footer.keybinds,
            vec![
                ("y/Y".to_string(), "cancel if needed + exit".to_string()),
                ("n/N/Esc".to_string(), "stay".to_string()),
            ]
        );
        assert_no_unimplemented_quit_claims(&model);
    }

    fn assert_no_unimplemented_quit_claims(model: &QuitConfirmModel) {
        let visible_copy = format!(
            "{} {:?} {:?}",
            model.warning_body, model.sections, model.footer.keybinds
        );
        for unsupported in ["checkpoint", "story", "detach", "resumable"] {
            assert!(
                !visible_copy.to_ascii_lowercase().contains(unsupported),
                "quit confirmation must not advertise unsupported `{unsupported}` behavior"
            );
        }
    }
}
