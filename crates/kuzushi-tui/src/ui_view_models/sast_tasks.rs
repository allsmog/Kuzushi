use crate::{SastTaskMode, SastTaskRow, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SastTasksModel {
    pub(crate) mode_label: &'static str,
    pub(crate) selected_summary: String,
    pub(crate) rows: Vec<SastTaskRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainSastTasksModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<String>,
    pub(crate) headers: [&'static str; 5],
    pub(crate) rows: Vec<PlainSastTaskRow>,
    pub(crate) next_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainSastTaskRow {
    pub(crate) state: &'static str,
    pub(crate) id: &'static str,
    pub(crate) cost: &'static str,
    pub(crate) scan_task: &'static str,
    pub(crate) notes: &'static str,
}

pub(crate) fn sast_tasks_model(app: &ShellApp) -> SastTasksModel {
    let rows = app.sast_task_rows();
    SastTasksModel {
        mode_label: mode_label(app.current_sast_task_mode()),
        selected_summary: selected_summary(&rows),
        rows,
    }
}

pub(crate) fn plain_sast_tasks_model(app: &ShellApp) -> PlainSastTasksModel {
    PlainSastTasksModel::from_sast_tasks_model(sast_tasks_model(app))
}

impl PlainSastTasksModel {
    fn from_sast_tasks_model(model: SastTasksModel) -> Self {
        PlainSastTasksModel {
            title: "SAST TASKS",
            summary_rows: vec![
                format!("mode: {}", model.mode_label),
                format!("selected: {}", model.selected_summary),
            ],
            headers: ["state", "id", "cost", "scan", "notes"],
            rows: model.rows.into_iter().map(plain_sast_task_row).collect(),
            next_hint:
                "Next: task block <id>, task allow <id>, task toggle [id], task mode auto|manual|toggle",
        }
    }
}

fn plain_sast_task_row(row: SastTaskRow) -> PlainSastTaskRow {
    PlainSastTaskRow {
        state: row.state,
        id: row.id,
        cost: row.cost,
        scan_task: row.scan_task,
        notes: row.notes,
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

    #[test]
    fn plain_sast_tasks_model_projects_plain_summary_and_table() {
        let app = ShellApp::new(V2Config::default(), None);

        let model = plain_sast_tasks_model(&app);

        assert_eq!(model.title, "SAST TASKS");
        assert_eq!(model.headers, ["state", "id", "cost", "scan", "notes"]);
        assert!(model
            .summary_rows
            .contains(&"mode: auto + denylist".to_string()));
        assert!(model.rows.iter().any(|row| row.id == "semgrep"));
        assert_eq!(
            model.next_hint,
            "Next: task block <id>, task allow <id>, task toggle [id], task mode auto|manual|toggle"
        );
    }
}
