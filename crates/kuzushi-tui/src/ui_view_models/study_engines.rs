//! Engine choices project existing SAST tasks and the shared scope contract.
use crate::app::ShellApp;
use crate::renderer::shared::text::wrap_text;
use ratatui::layout::Rect;
use serde_json::{json, Value};

pub(crate) struct StudyEngineRow {
    pub id: Option<String>,
    pub label: String,
    pub notes: String,
    pub selected: bool,
    pub unsupported: Option<String>,
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
    }];
    rows.extend(app.sast_task_rows().into_iter().map(|task| StudyEngineRow {
        id: Some(task.id.into()),
        label: task.id.into(),
        notes: task.notes.into(),
        selected: !picker.automatic && picker.selected.contains(task.id),
        unsupported: selection_support(&picker.input, Some(task.id)),
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
    if let Some(row) = rows.get(picker.cursor) {
        lines.push(row.label.clone());
        lines.push(row.unsupported.as_ref().map_or_else(
            || {
                "Supports this scope. Execution still requires dependency and allowance checks."
                    .into()
            },
            |reason| format!("UNSUPPORTED: {reason}"),
        ));
        lines.push(row.notes.clone());
    }
    lines.extend([String::new(), "Space or Enter toggles an engine. The first explicit choice replaces automatic selection. Unsupported saved choices can be removed.".into(),
        "a applies this draft; Esc cancels. A changed selection requires a new immutable plan and approval. Existing spending is retained. No jobs start.".into(),
        "Provider cost is uncertain for model-backed engines. Native tools still consume time and subprocess resources; this picker supplies no cost guarantee.".into()]);
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
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
    if app
        .study_engine_picker()
        .and_then(|picker| picker.conflicting_paths())
        .is_some()
    {
        "a apply · x clear · Esc cancel"
    } else {
        "a apply choices · Esc cancel"
    }
}

pub(crate) fn engine_line(row: &StudyEngineRow, focused: bool) -> String {
    let cursor = if focused { "▸" } else { " " };
    let selected = if row.selected { "[x]" } else { "[ ]" };
    let state = if row.unsupported.is_some() {
        " · unsupported"
    } else {
        ""
    };
    format!("{cursor} {selected} {}{state}", row.label)
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
