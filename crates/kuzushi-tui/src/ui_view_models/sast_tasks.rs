use crate::{SastTaskMode, SastTaskRow, ShellApp};

const SAST_TASK_SUMMARY_COLUMN_COUNT: usize = 2;
const SAST_TASK_COLUMN_COUNT: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SastTasksModel {
    pub(crate) title: &'static str,
    pub(crate) summary_rows: Vec<SastTaskSummaryRow>,
    pub(crate) legend: &'static str,
    pub(crate) headers: [&'static str; 5],
    pub(crate) rows: Vec<SastTaskDisplayRow>,
    pub(crate) command_hints: [&'static str; 5],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SastTaskSummaryRow {
    pub(crate) cells: [String; SAST_TASK_SUMMARY_COLUMN_COUNT],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SastTaskDisplayRow {
    pub(crate) cells: [String; SAST_TASK_COLUMN_COUNT],
    pub(crate) selected: bool,
    pub(crate) source: &'static str,
    pub(crate) task_id: &'static str,
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
    pub(crate) cells: [String; SAST_TASK_COLUMN_COUNT],
}

pub(crate) fn sast_tasks_model(app: &ShellApp) -> SastTasksModel {
    let task_rows = app.sast_task_rows();
    let rows = task_rows
        .into_iter()
        .map(sast_task_display_row)
        .collect::<Vec<_>>();
    SastTasksModel {
        title: "SAST TASKS",
        summary_rows: vec![
            sast_task_summary_row("mode", mode_label(app.current_sast_task_mode())),
            sast_task_summary_row("selected", &selected_summary(&rows)),
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

fn sast_task_display_row(row: SastTaskRow) -> SastTaskDisplayRow {
    SastTaskDisplayRow {
        cells: [
            row.state.to_string(),
            row.id.to_string(),
            row.cost.to_string(),
            row.scan_task.to_string(),
            row.notes.to_string(),
        ],
        selected: row.selected,
        source: row.source,
        task_id: row.id,
    }
}

fn sast_task_summary_row(label: &'static str, value: &str) -> SastTaskSummaryRow {
    SastTaskSummaryRow {
        cells: [label.to_string(), value.to_string()],
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
    let [label, value] = row.cells;
    format!("{label}: {value}")
}

fn plain_sast_task_row(row: SastTaskDisplayRow) -> PlainSastTaskRow {
    PlainSastTaskRow { cells: row.cells }
}

fn mode_label(mode: SastTaskMode) -> &'static str {
    match mode {
        SastTaskMode::Auto => "auto + denylist",
        SastTaskMode::Manual => "manual allowlist",
    }
}

fn selected_summary(rows: &[SastTaskDisplayRow]) -> String {
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
            .any(|row| row.cells[0] == "mode" && row.cells[1] == "auto + denylist"));
        assert!(model
            .summary_rows
            .iter()
            .any(|row| row.cells[0] == "selected" && row.cells[1].contains("enabled")));
        assert!(model.rows.iter().any(|row| row.task_id == "semgrep"));
        assert!(model.rows.iter().any(|row| row.task_id == "cargo-audit"));
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
            .any(|row| row.cells[0] == "mode" && row.cells[1] == "manual allowlist"));
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
        assert!(model.rows.iter().any(|row| row.cells[1] == "semgrep"));
        assert!(model.rows.iter().any(|row| row.cells[1] == "cargo-audit"));
        assert_eq!(
            model.next_hint,
            "Next: task block <id>, task allow <id>, task toggle [id], task mode auto|manual|toggle"
        );
    }
}
