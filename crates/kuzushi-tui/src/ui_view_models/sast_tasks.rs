use crate::{SastTaskMode, SastTaskRow, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SastTasksModel {
    pub(crate) mode_label: &'static str,
    pub(crate) selected_summary: String,
    pub(crate) rows: Vec<SastTaskRow>,
}

pub(crate) fn sast_tasks_model(app: &ShellApp) -> SastTasksModel {
    let rows = app.sast_task_rows();
    SastTasksModel {
        mode_label: mode_label(app.current_sast_task_mode()),
        selected_summary: selected_summary(&rows),
        rows,
    }
}

fn mode_label(mode: SastTaskMode) -> &'static str {
    match mode {
        SastTaskMode::Auto => "auto + denylist",
        SastTaskMode::Manual => "manual allowlist",
    }
}

fn selected_summary(rows: &[SastTaskRow]) -> String {
    let enabled = rows.iter().filter(|row| row.selected).count();
    let blocked = rows.iter().filter(|row| row.source == "blocked").count();
    format!("{enabled}/{} enabled, {blocked} blocked", rows.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{OptionScope, OptionTarget, V2Config};

    #[test]
    fn sast_tasks_model_reports_auto_mode_summary() {
        let app = ShellApp::new(V2Config::default(), None);

        let model = sast_tasks_model(&app);

        assert_eq!(model.mode_label, "auto + denylist");
        assert!(model.selected_summary.contains("enabled"));
        assert!(model.rows.iter().any(|row| row.id == "semgrep"));
    }

    #[test]
    fn sast_tasks_model_reports_manual_mode_summary() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.option_store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "taskMode",
            serde_json::json!("manual"),
        );

        let model = sast_tasks_model(&app);

        assert_eq!(model.mode_label, "manual allowlist");
        assert!(model.rows.iter().all(|row| row.source != "default"));
    }
}
