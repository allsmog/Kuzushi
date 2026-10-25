//! Engine choices project existing SAST tasks and the shared scope contract.
use crate::app::ShellApp;
use crate::renderer::shared::text::wrap_text;
use ratatui::layout::Rect;
use serde_json::{json, Value};
mod readiness;
pub(crate) use readiness::selected_engine_requirements;

pub(crate) struct StudyEngineRow {
    pub id: Option<String>,
    pub label: String,
    pub notes: String,
    pub selected: bool,
    pub unsupported: Option<String>,
    pub readiness: readiness::EngineReadiness,
}

pub(crate) fn engine_rows(app: &ShellApp) -> Vec<StudyEngineRow> {
    let Some(picker) = app.study_engine_picker() else {
        return Vec::new();
    };
    let mut rows = vec![StudyEngineRow {
        id: None, label: "Automatic selection".into(),
        notes: "Retain automatic engine resolution. Availability is checked during preparation; no engines are silently substituted.".into(),
        selected: picker.automatic,
        unsupported: selection_support(&picker.prepared_selection(), None),
        readiness: readiness::automatic(),
    }];
    rows.extend(app.sast_task_rows().into_iter().map(|task| StudyEngineRow {
        id: Some(task.id.into()),
        label: task.id.into(),
        notes: task.notes.into(),
        selected: !picker.automatic && picker.selected.contains(task.id),
        unsupported: selection_support(&picker.input, Some(task.id)),
        readiness: readiness::task_readiness(app, task.id, &picker.input),
    }));
    append_unknown_engines(&mut rows, &picker.selected);
    rows
}

fn append_unknown_engines(
    rows: &mut Vec<StudyEngineRow>,
    selected: &std::collections::BTreeSet<String>,
) {
    for id in selected {
        if rows.iter().any(|row| row.id.as_ref() == Some(id)) {
            continue;
        }
        rows.push(StudyEngineRow {
            id: Some(id.clone()),
            label: id.clone(),
            notes: "Saved selection has no registered task. Remove it to prepare a new study."
                .into(),
            selected: true,
            unsupported: Some("Unregistered engine".into()),
            readiness: readiness::unregistered(),
        });
    }
}

fn selection_support(original: &Value, task: Option<&str>) -> Option<String> {
    let mut input = original.clone();
    if let Some(task) = task {
        input["taskMode"] = json!("manual");
        input["tasks"] = json!([task]);
    } else {
        input["taskMode"] = json!("auto");
        input.as_object_mut()?.remove("tasks");
    }
    kuzushi_core::modules::validate_scan_scope_contract(&input)
        .err()
        .map(|error| format!("{error:#}"))
}

pub(crate) fn engine_layout(
    columns: u16,
    rows: u16,
    count: usize,
) -> super::study_config::StudyConfigLayout {
    let area = super::study_config::study_config_area(columns, rows);
    let mut layout = super::study_config::study_config_layout(area);
    if layout.list.x == layout.detail.x {
        let spare = layout
            .list
            .height
            .saturating_sub(count.min(u16::MAX as usize) as u16);
        layout.list.height -= spare;
        layout.detail.y -= spare;
        layout.detail.height += spare;
    }
    layout
}

pub(crate) fn engine_detail(app: &ShellApp, width: usize) -> Vec<String> {
    let Some(picker) = app.study_engine_picker() else {
        return Vec::new();
    };
    let rows = engine_rows(app);
    let mut lines = Vec::new();
    if let Some(notice) = &picker.notice {
        lines.extend([notice.clone(), String::new()]);
    }
    lines.extend(path_conflict_lines(picker));
    lines.extend(inactive_option_lines(picker));
    if let Some(row) = rows.get(picker.cursor) {
        lines.extend(selected_engine_detail(row));
    }
    lines.extend([String::new(), "Space or Enter toggles an engine. The first explicit choice replaces automatic selection. Unsupported saved choices can be removed.".into(),
        "a applies this draft; Esc cancels. A changed selection requires a new immutable plan and approval. Existing spending is retained. No jobs start.".into(),
        "r rechecks executable presence without running commands. Provider cost is uncertain for model-backed engines. Native tools still consume time and subprocess resources; this picker supplies no cost guarantee.".into()]);
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn selected_engine_detail(row: &StudyEngineRow) -> Vec<String> {
    let mut lines = vec![format!("{}{}", row.label, row.readiness.suffix)];
    if let Some(reason) = &row.unsupported {
        lines.push(format!("UNSUPPORTED: {reason}"));
    }
    lines.extend(row.readiness.details.clone());
    if row.unsupported.is_none() {
        lines.push(
            "Scope contract supported. Source membership is checked during preparation.".into(),
        );
    }
    lines.push(row.notes.clone());
    lines
}

fn path_conflict_lines(picker: &crate::app::StudyEnginePicker) -> Vec<String> {
    let Some(paths) = picker.conflicting_paths() else {
        return Vec::new();
    };
    let mut lines = vec![
        "Earlier path filters conflict with the accepted scope.".into(),
        format!(
            "Accepted scope: {}",
            picker.input["scanScopeRef"]["scopeId"]
                .as_str()
                .unwrap_or("unavailable")
        ),
        "Earlier filters:".into(),
    ];
    lines.extend(
        paths
            .iter()
            .filter_map(Value::as_str)
            .map(|path| format!("  {path}")),
    );
    lines.extend(["x clears these filters for this draft. The accepted boundary becomes the only discovery scope. Global settings stay unchanged. Apply the draft and review a new plan before work starts.".into(), String::new()]);
    lines
}

pub(crate) fn engine_apply_controls(app: &ShellApp) -> &'static str {
    if app.study_engine_picker().is_some_and(has_inactive_options) {
        return "c clear unused · a apply · Esc";
    }
    scope_engine_apply_controls(app)
}

fn has_inactive_options(picker: &crate::app::StudyEnginePicker) -> bool {
    picker
        .inactive_options()
        .is_ok_and(|groups| !groups.is_empty())
}

fn scope_engine_apply_controls(app: &ShellApp) -> &'static str {
    let paths = app
        .study_engine_picker()
        .and_then(|picker| picker.conflicting_paths())
        .is_some();
    let files = app
        .study_engine_picker()
        .is_some_and(|picker| picker.needs_scoped_file_tools());
    match (paths, files) {
        (true, true) => "a apply · x clear · m files · Esc",
        (true, false) => "a apply · x clear · Esc cancel",
        (false, true) => "a apply choices · m files · Esc",
        (false, false) => "a apply choices · Esc cancel",
    }
}

fn inactive_option_lines(picker: &crate::app::StudyEnginePicker) -> Vec<String> {
    let groups = match picker.inactive_options() {
        Ok(groups) => groups,
        Err(error) => return vec![format!("Option selection needs attention: {error:#}")],
    };
    if groups.is_empty() {
        return Vec::new();
    }
    let mut lines = vec!["Settings belong to unselected engines:".into()];
    lines.extend(
        groups
            .into_iter()
            .map(|group| format!("{}: {}", group.task, group.options.join(", "))),
    );
    lines.extend(["c clears only these settings in this draft. Or select their engines. Esc keeps the original study. Global settings and spending stay unchanged.".into(),String::new()]);
    lines
}

pub(crate) fn engine_line(row: &StudyEngineRow, focused: bool) -> String {
    let cursor = if focused { "▸" } else { " " };
    let selected = if row.selected { "[x]" } else { "[ ]" };
    let state = if row.unsupported.is_some() {
        " · unsupported"
    } else {
        ""
    };
    format!(
        "{cursor} {selected} {}{}{state}{}",
        row.readiness.badge, row.label, row.readiness.suffix
    )
}

pub(crate) fn engine_area(frame: Rect) -> Rect {
    super::study_config::study_config_area(frame.width, frame.height)
}

pub(crate) fn engine_read_position(app: &ShellApp, area: Rect) -> String {
    let count = engine_detail(app, area.width as usize).len();
    let height = area.height.max(1) as usize;
    let max = count.saturating_sub(height);
    let scroll = app
        .study_engine_picker()
        .map_or(0, |picker| picker.scroll.min(max));
    format!(
        "{}-{} of {}",
        scroll + 1,
        (scroll + height).min(count),
        count
    )
}
