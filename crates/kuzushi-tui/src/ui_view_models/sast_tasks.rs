use crate::{SastTaskMode, SastTaskRow, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SastTasksModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<SastTaskSummaryRow>,
    pub(crate) legend: &'static str,
    pub(crate) headers: [&'static str; 5],
    pub(crate) rows: Vec<SastTaskRow>,
    pub(crate) command_hints: [&'static str; 5],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SastTaskSummaryRow {
    pub(crate) label: &'static str,
    pub(crate) value: String,
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
        title: "SAST TASKS",
        summary_rows: vec![
            SastTaskSummaryRow {
                label: "mode",
                value: mode_label(app.current_sast_task_mode()).to_string(),
            },
            SastTaskSummaryRow {
                label: "selected",
                value: selected_summary(&rows),
            },
        ],
        legend:
            "legend: [x] enabled · [ ] disabled · [A] advanced (off by default; allow with /task allow <id>) · [B] blocked",
        headers: ["state", "id", "cost", "scan", "notes"],
        rows,
        command_hints: [
            "/task block <id>",
            "/task allow <id>",
            "/task toggle [id]",
            "/task mode auto|manual|toggle",
            "/task reset",
        ],
    }
}

pub(crate) fn plain_sast_tasks_model(app: &ShellApp) -> PlainSastTasksModel {
    PlainSastTasksModel::from_sast_tasks_model(sast_tasks_model(app))
}

impl PlainSastTasksModel {
    fn from_sast_tasks_model(model: SastTasksModel) -> Self {
        PlainSastTasksModel {
            title: model.title,
            summary_rows: model
                .summary_rows
                .into_iter()
                .map(plain_sast_task_summary_row)
                .collect(),
            headers: model.headers,
            rows: model.rows.into_iter().map(plain_sast_task_row).collect(),
            next_hint:
                "Next: task block <id>, task allow <id>, task toggle [id], task mode auto|manual|toggle",
        }
    }
}

fn plain_sast_task_summary_row(row: SastTaskSummaryRow) -> String {
    format!("{}: {}", row.label, row.value)
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

        assert_eq!(model.title, "SAST TASKS");
        assert!(model.legend.contains("advanced"));
        assert_eq!(model.headers, ["state", "id", "cost", "scan", "notes"]);
        assert!(model.command_hints.contains(&"/task reset"));
        assert!(model
            .summary_rows
            .iter()
            .any(|row| row.label == "mode" && row.value == "auto + denylist"));
        assert!(model
            .summary_rows
            .iter()
            .any(|row| row.label == "selected" && row.value.contains("enabled")));
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

        assert!(model
            .summary_rows
            .iter()
            .any(|row| row.label == "mode" && row.value == "manual allowlist"));
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
