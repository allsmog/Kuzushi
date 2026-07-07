use super::*;
use crate::app::{
    format_option_value, row_disposition, PickerFocus, PlanningArtifactState, PlanningTaskRow,
    WorkflowPhase,
};
use crate::ui_view_models::{
    enter_plan, format_relative_age, journey_model, latest_cached_modified, workspace_history,
    JourneyPhaseState, JourneyPhaseStatus, JourneyPhaseTone, RowOutcome, WorkspaceHistory,
};
use kuzushi_core::modules::OptionSpec;
use kuzushi_core::OptionScope;
use serde_json::Value;
use std::time::SystemTime;

pub(crate) fn planning_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    push_phase_header(app, area.width, &mut lines);
    if app.engagement.planning_picker().tasks().is_empty() {
        lines.push(muted("(no tasks in this phase)"));
        return lines;
    }
    lines.push(blank());
    lines.push(prior_state_banner(app));
    lines.push(blank());
    lines.push(legend_line(area.width));
    lines.push(blank());
    if area.width as usize >= MASTER_DETAIL_WIDTH {
        push_master_detail_rows(app, area.width, &mut lines);
    } else {
        lines.extend(task_list_pane_lines(app, area.width));
        lines.push(blank());
        lines.extend(planning_options_pane_lines(app, area.width as usize));
    }
    lines.push(blank());
    lines.push(enter_summary_line(app));
    lines
}

/// Announce the current judo phase (組→崩→作→掛) and its intent.
fn push_phase_header(app: &ShellApp, width: u16, lines: &mut Vec<Line<'static>>) {
    match app.engagement.current_phase() {
        Some(phase) => {
            lines.push(divider(phase.label(), width));
            lines.push(blank());
            push_phase_rail(app, width, lines);
            lines.push(muted(&format!(
                "phase {} of {} — {}",
                phase.position(),
                WorkflowPhase::ORDER.len(),
                phase.intent()
            )));
        }
        None => {
            lines.push(divider("PLAN THE WORKSPACE", width));
            lines.push(blank());
            lines.push(muted(
                "Select tasks. Dependencies auto-toggle. Steps run in order.",
            ));
        }
    }
}

fn push_phase_rail(app: &ShellApp, width: u16, lines: &mut Vec<Line<'static>>) {
    if let Some(journey) = journey_model(app) {
        lines.push(phase_rail_line(&journey.phases, width as usize));
        return;
    }
    if let Some(current) = app.engagement.current_phase() {
        lines.push(fallback_phase_rail_line(current, width as usize));
    }
}

fn phase_rail_line(phases: &[JourneyPhaseStatus], width: usize) -> Line<'static> {
    let mut spans = vec![
        Span::styled("‹h ", theme::accent()),
        Span::styled("phase ", theme::muted()),
    ];
    for (idx, phase) in phases.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::styled("  ", theme::subtle()));
        }
        push_phase_segment(&mut spans, idx, phase);
    }
    spans.push(Span::styled(" l›", theme::accent()));
    fit_spans(spans, width)
}

fn push_phase_segment(spans: &mut Vec<Span<'static>>, index: usize, phase: &JourneyPhaseStatus) {
    let label = phase.phase_label.trim();
    let text = format!("{} {label} {}", index + 1, phase.state_symbol);
    if phase.state == JourneyPhaseState::Current {
        spans.push(Span::styled("[", theme::warn()));
        spans.push(Span::styled(text, phase_tone_style(phase.tone)));
        spans.push(Span::styled("]", theme::warn()));
    } else {
        spans.push(Span::styled(text, phase_tone_style(phase.tone)));
    }
}

fn fallback_phase_rail_line(current: WorkflowPhase, width: usize) -> Line<'static> {
    let statuses: Vec<JourneyPhaseStatus> = WorkflowPhase::ORDER
        .iter()
        .map(|&phase| JourneyPhaseStatus {
            phase,
            state: if phase == current {
                JourneyPhaseState::Current
            } else {
                JourneyPhaseState::Pending
            },
            phase_label: fallback_phase_rail_label(phase),
            state_symbol: if phase == current { "●" } else { "·" },
            tone: if phase == current {
                JourneyPhaseTone::Warn
            } else {
                JourneyPhaseTone::Subtle
            },
        })
        .collect();
    phase_rail_line(&statuses, width)
}

fn fallback_phase_rail_label(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Map => "組 map",
        WorkflowPhase::Hunt => "崩 hunt",
        WorkflowPhase::Confirm => "作 confirm",
        WorkflowPhase::Fix => "掛 fix",
    }
}

fn phase_tone_style(tone: JourneyPhaseTone) -> Style {
    match tone {
        JourneyPhaseTone::Success => theme::success(),
        JourneyPhaseTone::Warn => theme::warn(),
        JourneyPhaseTone::Danger => theme::danger(),
        JourneyPhaseTone::Muted => theme::muted(),
        JourneyPhaseTone::Subtle => theme::subtle(),
    }
}

fn fit_spans(spans: Vec<Span<'static>>, width: usize) -> Line<'static> {
    let text_width = spans_width(&spans);
    if text_width <= width {
        return Line::from(spans);
    }
    let text: String = spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<Vec<_>>()
        .join("");
    Line::styled(fit(&text, width), theme::subtle())
}

/// Tell a returning operator, up front, whether Kuzushi found prior work for
/// this target — the single biggest missing signal in the old picker.
fn prior_state_banner(app: &ShellApp) -> Line<'static> {
    let last_activity = latest_cached_modified(app.engagement.planning_picker().tasks())
        .and_then(|then| format_relative_age(SystemTime::now(), then));
    let map_artifacts_built = app
        .workbench_cache()
        .borrow_mut()
        .map_artifacts_built(app.target());
    match workspace_history(
        app.engagement.planning_picker().tasks(),
        app.findings().len(),
        map_artifacts_built,
        last_activity,
    ) {
        WorkspaceHistory::Fresh => Line::from(vec![
            Span::styled("▌ ", theme::subtle()),
            Span::styled("Fresh target".to_string(), theme::label()),
            Span::styled(
                " — no prior Kuzushi state here; everything below is new work.".to_string(),
                theme::muted(),
            ),
        ]),
        WorkspaceHistory::Prior(state) => prior_state_line(app, state.headline()),
    }
}

fn prior_state_line(app: &ShellApp, headline: String) -> Line<'static> {
    if revisiting_cached_artifact_phase(app) {
        return Line::from(vec![
            Span::styled("▌ ", theme::accent()),
            Span::styled(
                "Revisiting — artifacts cached; press g to rebuild".to_string(),
                theme::accent().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" ({headline})"), theme::muted()),
        ]);
    }
    Line::from(vec![
        Span::styled("▌ ", theme::success()),
        Span::styled(
            "Resuming — Kuzushi found prior work: ".to_string(),
            theme::success().add_modifier(Modifier::BOLD),
        ),
        Span::styled(headline, theme::primary()),
    ])
}

fn revisiting_cached_artifact_phase(app: &ShellApp) -> bool {
    app.engagement.current_phase().is_some()
        && app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .any(|row| matches!(row.artifact_state, PlanningArtifactState::Cached))
        && app.engagement.planning_picker().tasks().iter().all(|row| {
            matches!(
                row.artifact_state,
                PlanningArtifactState::Cached | PlanningArtifactState::Action
            )
        })
}

/// A colour-keyed legend so the outcome words in the rows are never load-
/// bearing on their own. Full glosses when they fit; just the coloured words
/// on a narrow terminal.
fn legend_line(width: u16) -> Line<'static> {
    let full = legend_spans(true);
    if spans_width(&full) <= width as usize {
        return Line::from(full);
    }
    Line::from(legend_spans(false))
}

fn legend_spans(with_gloss: bool) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled(" outcome: ", theme::muted())];
    for (idx, outcome) in RowOutcome::LEGEND.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::styled("   ", theme::subtle()));
        }
        spans.push(Span::styled(
            outcome.word().to_string(),
            outcome_style(*outcome),
        ));
        if with_gloss {
            spans.push(Span::styled(
                format!(" {}", outcome.gloss()),
                theme::muted(),
            ));
        }
    }
    spans
}

fn spans_width(spans: &[Span<'static>]) -> usize {
    spans.iter().map(|span| span.content.chars().count()).sum()
}

/// A subtle column header so operators can read the grid. Dropped entirely on
/// very narrow terminals, where rows collapse to outcome + task.
fn column_header(width: u16) -> Option<Line<'static>> {
    let w = width as usize;
    let body = if w >= WIDE {
        format!(
            "    {:<7} {:<30} {:<22} {}",
            "OUTCOME", "TASK", "TOOL", "WHY"
        )
    } else if w >= MEDIUM {
        format!("    {:<7} {:<28} {}", "OUTCOME", "TASK", "WHY")
    } else {
        return None;
    };
    Some(styled(&fit(&body, w), theme::subtle()))
}

const WIDE: usize = 88;
const MEDIUM: usize = 60;
const MASTER_DETAIL_WIDTH: usize = 118;

fn push_master_detail_rows(app: &ShellApp, width: u16, lines: &mut Vec<Line<'static>>) {
    let w = width as usize;
    let detail_width = (w / 3).clamp(38, 52);
    let list_width = w.saturating_sub(detail_width + 2);
    let left = task_list_pane_lines(app, list_width as u16);
    let right = planning_options_pane_lines(app, detail_width);
    let row_count = left.len().max(right.len());
    for idx in 0..row_count {
        lines.push(join_pane_lines(
            left.get(idx).cloned(),
            right.get(idx).cloned(),
            list_width,
        ));
    }
}

fn task_list_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(header) = column_header(width) {
        lines.push(header);
    }
    for (idx, row) in app.engagement.planning_picker().tasks().iter().enumerate() {
        lines.push(planning_row_line(app, idx, row, width));
    }
    lines
}

fn task_list_pane_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let width = (width as usize).max(24);
    let focused = app.engagement.planning_picker().focus() == PickerFocus::List;
    let border_style = pane_border_style(focused);
    let mut lines = vec![border_line(
        "┌",
        pane_title(" TASKS ", focused).as_str(),
        "┐",
        width,
        border_style,
        pane_title_style(focused),
    )];
    lines.extend(
        task_list_lines(app, width.saturating_sub(4) as u16)
            .into_iter()
            .map(|line| pane_line(line, width, border_style)),
    );
    lines.push(border_line(
        "└",
        "",
        "┘",
        width,
        border_style,
        theme::label(),
    ));
    lines
}

fn join_pane_lines(
    left: Option<Line<'static>>,
    right: Option<Line<'static>>,
    left_width: usize,
) -> Line<'static> {
    let mut left = left.unwrap_or_else(blank);
    let current_width = spans_width(&left.spans);
    if current_width < left_width {
        left.spans
            .push(Span::raw(" ".repeat(left_width - current_width)));
    }
    left.spans.push(Span::raw("  "));
    if let Some(right) = right {
        left.spans.extend(right.spans);
    }
    left
}

fn planning_row_line(
    app: &ShellApp,
    idx: usize,
    row: &PlanningTaskRow,
    width: u16,
) -> Line<'static> {
    let disposition = row_disposition(
        row,
        app.engagement.planning_picker().selected(),
        app.engagement.planning_picker().rebuild(),
    );
    let outcome = RowOutcome::from_disposition(disposition);
    let marker = planning_row_marker(app, idx);
    let note = planning_row_note(app, row, outcome);
    let label = planning_row_label(app, row);
    let w = width as usize;
    let body = planning_row_body(w, marker, outcome, &label, row.tool_name, &note);
    Line::styled(fit(&body, w), planning_row_style(app, idx, outcome))
}

fn planning_row_marker(app: &ShellApp, idx: usize) -> &'static str {
    if idx == app.engagement.planning_picker().cursor() {
        ">"
    } else {
        " "
    }
}

fn planning_row_body(
    width: usize,
    marker: &str,
    outcome: RowOutcome,
    label: &str,
    tool_name: &str,
    note: &str,
) -> String {
    if width >= WIDE {
        return format!(
            "  {marker} {outcome:<7} {label:<30} {tool_name:<22} {note}",
            outcome = outcome.word(),
        );
    }
    if width >= MEDIUM {
        return format!(
            "  {marker} {outcome:<7} {label:<28} {note}",
            outcome = outcome.word(),
        );
    }
    format!("  {marker} {outcome:<7} {label}", outcome = outcome.word())
}

fn planning_row_label(app: &ShellApp, row: &PlanningTaskRow) -> String {
    let count = app.planning_override_count(row.id);
    if count == 0 {
        row.label.to_string()
    } else {
        format!("{} ∙{}", row.label, count)
    }
}

/// The row's "why" column: the artifact reality plus the one cost/blocker the
/// operator needs to act on, phrased so it agrees with the outcome word.
fn planning_row_note(app: &ShellApp, row: &PlanningTaskRow, outcome: RowOutcome) -> String {
    blocked_row_note(row, outcome)
        .or_else(|| cached_row_note(row, outcome))
        .or_else(|| missing_model_note(app, row))
        .unwrap_or_else(|| outcome_row_note(app, row, outcome))
}

fn blocked_row_note(row: &PlanningTaskRow, outcome: RowOutcome) -> Option<String> {
    (outcome == RowOutcome::Blocked).then(|| {
        format!(
            "blocked — install {} for this step",
            row.required_cli.unwrap_or("a tool")
        )
    })
}

fn cached_row_note(row: &PlanningTaskRow, outcome: RowOutcome) -> Option<String> {
    if !matches!(row.artifact_state, PlanningArtifactState::Cached) {
        return None;
    }
    if let Some(cli) = row.required_cli.filter(|_| !row.cli_available) {
        return Some(format!("cached — rebuild needs {cli}"));
    }
    (outcome == RowOutcome::Reuse).then(|| "cached — press g to rebuild".to_string())
}

fn missing_model_note(app: &ShellApp, row: &PlanningTaskRow) -> Option<String> {
    (row.model_backed && app.config().model.is_none())
        .then(|| "needs model — run /model first".to_string())
}

fn outcome_row_note(app: &ShellApp, row: &PlanningTaskRow, outcome: RowOutcome) -> String {
    match outcome {
        RowOutcome::Run if app.engagement.planning_picker().rebuild().contains(&row.id) => {
            with_cost(row, "rebuild (overwrites cache)")
        }
        RowOutcome::Run | RowOutcome::Skip => with_cost(row, artifact_reason(row)),
        RowOutcome::Reuse | RowOutcome::Blocked => unreachable!("handled above"),
    }
}

fn artifact_reason(row: &PlanningTaskRow) -> &'static str {
    match row.artifact_state {
        PlanningArtifactState::Cached => "cached",
        PlanningArtifactState::Missing => "not built yet",
        PlanningArtifactState::Invalid => "cached but invalid",
        PlanningArtifactState::Action => "runs a scan/action",
    }
}

fn with_cost(row: &PlanningTaskRow, base: &str) -> String {
    let mut parts = vec![base.to_string()];
    if row.model_backed {
        parts.push("model-backed".to_string());
    }
    if let Some(cli) = row.required_cli.filter(|_| row.cli_available) {
        parts.push(format!("{cli} ready"));
    }
    parts.join(" · ")
}

fn planning_options_pane_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let width = width.max(24);
    let Some(row) = app.engagement.planning_picker().current_row() else {
        return bordered_message("options", "no focused step", width);
    };
    let focused = app.engagement.planning_picker().focus() == PickerFocus::OptionsPane;
    let border_style = pane_border_style(focused);
    let title = pane_title(&format!(" {} ", row.tool_name), focused);
    let Some(tool) = app.registry().resolve_tool(row.tool_name) else {
        return bordered_message(&title, "tool descriptor missing", width);
    };
    let mut lines = option_pane_header(&title, focused, border_style, width);
    append_option_pane_rows(&mut lines, app, row, &tool.options, width);
    append_option_pane_error(&mut lines, app, border_style, width);
    lines.push(pane_separator(width, border_style));
    lines.push(input_preview_line(app, row, width));
    lines.push(border_line(
        "└",
        "",
        "┘",
        width,
        border_style,
        theme::label(),
    ));
    lines
}

fn option_pane_header(
    title: &str,
    focused: bool,
    border_style: Style,
    width: usize,
) -> Vec<Line<'static>> {
    vec![border_line(
        "┌",
        title,
        "┐",
        width,
        border_style,
        pane_title_style(focused),
    )]
}

fn append_option_pane_rows(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    row: &PlanningTaskRow,
    options: &[OptionSpec],
    width: usize,
) {
    if options.is_empty() {
        lines.push(pane_body_line(
            "no declared options",
            width,
            theme::muted(),
            pane_border_style(app.engagement.planning_picker().focus() == PickerFocus::OptionsPane),
        ));
        return;
    }
    let resolved = app.resolved_input_for_planning_task(row.id).ok();
    for (idx, spec) in options.iter().enumerate() {
        lines.push(option_pane_row(
            app,
            row,
            spec,
            idx,
            resolved.as_ref(),
            width,
        ));
    }
}

fn append_option_pane_error(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    border_style: Style,
    width: usize,
) {
    if let Some(error) = app.engagement.planning_picker().option_error() {
        lines.push(pane_body_line(
            &fit(error, width.saturating_sub(4)),
            width,
            theme::danger(),
            border_style,
        ));
    }
}

fn bordered_message(title: &str, message: &str, width: usize) -> Vec<Line<'static>> {
    let border_style = theme::subtle();
    vec![
        border_line("┌", title, "┐", width, border_style, theme::label()),
        pane_body_line(message, width, theme::muted(), border_style),
        border_line("└", "", "┘", width, border_style, theme::label()),
    ]
}

fn option_pane_row(
    app: &ShellApp,
    row: &PlanningTaskRow,
    spec: &OptionSpec,
    idx: usize,
    resolved: Option<&Value>,
    width: usize,
) -> Line<'static> {
    let selected = app.engagement.planning_picker().focus() == PickerFocus::OptionsPane
        && idx == app.engagement.planning_picker().option_cursor();
    let editing = app
        .engagement
        .planning_picker()
        .option_edit()
        .is_some_and(|edit| edit.task == row.id && edit.option_name == spec.name);
    let marker = if selected { ">" } else { " " };
    let value = option_display_value(app, spec, resolved, editing);
    let provenance = option_provenance(app, row, spec, resolved);
    let name = option_name_label(app, row, spec);
    let body_width = width.saturating_sub(4);
    let row_text = option_pane_row_text(marker, &name, &value, &provenance, body_width);
    let style = option_pane_row_style(selected, &provenance);
    pane_body_line(
        &fit(&row_text, body_width),
        width,
        style,
        pane_border_style(app.engagement.planning_picker().focus() == PickerFocus::OptionsPane),
    )
}

fn option_pane_row_text(
    marker: &str,
    name: &str,
    value: &str,
    provenance: &str,
    body_width: usize,
) -> String {
    if body_width >= 40 {
        return format!(
            "{marker} {name:<14} {value:<13} {provenance:<9}",
            name = fit(name, 14),
            value = fit(value, 13),
        );
    }
    format!("{marker} {name} {value} {provenance}")
}

fn option_pane_row_style(selected: bool, provenance: &str) -> Style {
    if selected {
        return theme::accent().add_modifier(Modifier::BOLD);
    }
    if provenance == "preset" {
        theme::muted()
    } else {
        theme::primary()
    }
}

fn option_name_label(app: &ShellApp, row: &PlanningTaskRow, spec: &OptionSpec) -> String {
    let suffix = if app.option_locked_by_planning_preset(row.id, &spec.name) {
        " lock"
    } else if spec.advanced {
        " adv"
    } else {
        ""
    };
    format!("{}{}", spec.name, suffix)
}

fn option_display_value(
    app: &ShellApp,
    spec: &OptionSpec,
    resolved: Option<&Value>,
    editing: bool,
) -> String {
    if editing {
        let draft = app
            .engagement
            .planning_picker()
            .option_edit()
            .map(|edit| edit.draft.as_str())
            .unwrap_or_default();
        return format!("{draft}_");
    }
    resolved
        .and_then(|input| input.get(&spec.name))
        .map(format_option_value)
        .unwrap_or_else(|| "-".to_string())
}

fn option_provenance(
    app: &ShellApp,
    row: &PlanningTaskRow,
    spec: &OptionSpec,
    resolved: Option<&Value>,
) -> &'static str {
    option_locked_provenance(app, row, spec)
        .or_else(|| option_override_provenance(app, row, spec))
        .or_else(|| option_stored_provenance(app, row, spec))
        .or_else(|| option_default_provenance(resolved, spec))
        .unwrap_or("-")
}

fn option_locked_provenance(
    app: &ShellApp,
    row: &PlanningTaskRow,
    spec: &OptionSpec,
) -> Option<&'static str> {
    if app.option_locked_by_planning_preset(row.id, &spec.name) {
        return Some("preset");
    }
    None
}

fn option_override_provenance(
    app: &ShellApp,
    row: &PlanningTaskRow,
    spec: &OptionSpec,
) -> Option<&'static str> {
    if app
        .engagement
        .option_override_value(row.id, &spec.name)
        .is_some()
    {
        return Some("this run");
    }
    None
}

fn option_stored_provenance(
    app: &ShellApp,
    row: &PlanningTaskRow,
    spec: &OptionSpec,
) -> Option<&'static str> {
    app.planning_option_stored_scope(row.tool_name, spec)
        .map(stored_scope_label)
}

fn option_default_provenance(resolved: Option<&Value>, spec: &OptionSpec) -> Option<&'static str> {
    if resolved.is_some_and(|input| input.get(&spec.name).is_some()) {
        return Some("default");
    }
    if spec.required {
        return Some("missing");
    }
    None
}

fn stored_scope_label(scope: OptionScope) -> &'static str {
    match scope {
        OptionScope::Global => "setg",
        OptionScope::Workspace => "workspace",
        OptionScope::Session => "set",
    }
}

fn input_preview_line(app: &ShellApp, row: &PlanningTaskRow, width: usize) -> Line<'static> {
    let preview = match app.resolved_input_for_planning_task(row.id) {
        Ok(input) => format!(
            "input {}",
            serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string())
        ),
        Err(error) => format!("input error: {error:#}"),
    };
    let style = if preview.starts_with("input error") {
        theme::danger()
    } else {
        theme::muted()
    };
    pane_body_line(
        &fit(&preview, width.saturating_sub(4)),
        width,
        style,
        pane_border_style(app.engagement.planning_picker().focus() == PickerFocus::OptionsPane),
    )
}

fn pane_separator(width: usize, border_style: Style) -> Line<'static> {
    border_line("├", "", "┤", width, border_style, theme::label())
}

fn pane_body_line(text: &str, width: usize, style: Style, border_style: Style) -> Line<'static> {
    let body_width = width.saturating_sub(4);
    Line::from(vec![
        Span::styled("│ ", border_style),
        Span::styled(format!("{:<body_width$}", fit(text, body_width)), style),
        Span::styled(" │", border_style),
    ])
}

fn pane_line(line: Line<'static>, width: usize, border_style: Style) -> Line<'static> {
    let body_width = width.saturating_sub(4);
    let line_width = spans_width(&line.spans).min(body_width);
    let mut spans = vec![Span::styled("│ ", border_style)];
    spans.extend(line.spans);
    if line_width < body_width {
        spans.push(Span::raw(" ".repeat(body_width - line_width)));
    }
    spans.push(Span::styled(" │", border_style));
    Line::from(spans)
}

fn border_line(
    left: &str,
    title: &str,
    right: &str,
    width: usize,
    border_style: Style,
    title_style: Style,
) -> Line<'static> {
    let inner_width = width.saturating_sub(2);
    let title = fit(title, inner_width);
    let fill = inner_width.saturating_sub(title.chars().count());
    Line::from(vec![
        Span::styled(left.to_string(), border_style),
        Span::styled(title, title_style),
        Span::styled("─".repeat(fill), border_style),
        Span::styled(right.to_string(), border_style),
    ])
}

fn pane_title(title: &str, focused: bool) -> String {
    if focused {
        format!("{title}FOCUS ")
    } else {
        title.to_string()
    }
}

fn pane_border_style(focused: bool) -> Style {
    if focused {
        theme::accent()
    } else {
        theme::subtle()
    }
}

fn pane_title_style(focused: bool) -> Style {
    if focused {
        theme::accent().add_modifier(Modifier::BOLD)
    } else {
        theme::label()
    }
}

/// State exactly what Enter will do, styled green only when something actually
/// runs — a reused/skipped-only plan stays muted so the colour can't overclaim.
fn enter_summary_line(app: &ShellApp) -> Line<'static> {
    let plan = enter_plan(
        app.engagement.planning_picker().tasks(),
        app.engagement.planning_picker().selected(),
        app.engagement.planning_picker().rebuild(),
    );
    let style = if plan.run > 0 {
        theme::success().add_modifier(Modifier::BOLD)
    } else {
        theme::muted()
    };
    styled(&format!(" {}", plan.summary_line()), style)
}

fn outcome_style(outcome: RowOutcome) -> Style {
    match outcome {
        RowOutcome::Run => theme::success(),
        RowOutcome::Reuse => theme::accent(),
        RowOutcome::Skip => theme::subtle(),
        RowOutcome::Blocked => theme::danger(),
    }
}

/// Green is reserved for rows Enter will actually run; reused rows stay muted,
/// skipped rows dim, blocked rows disabled — the colour tracks the outcome word.
fn planning_row_style(app: &ShellApp, idx: usize, outcome: RowOutcome) -> Style {
    let base = match outcome {
        RowOutcome::Run => theme::success(),
        RowOutcome::Reuse => theme::muted(),
        RowOutcome::Skip => theme::primary(),
        RowOutcome::Blocked => theme::disabled(),
    };
    if idx == app.engagement.planning_picker().cursor() {
        return planning_cursor_style(base, outcome);
    }
    base
}

fn planning_cursor_style(base: Style, outcome: RowOutcome) -> Style {
    if outcome == RowOutcome::Run {
        base.add_modifier(Modifier::BOLD)
    } else {
        theme::accent().add_modifier(Modifier::BOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn legend_drops_glosses_when_it_cannot_fit() {
        let wide = legend_line(200);
        assert!(line_text(&wide).contains("runs now"), "wide keeps glosses");
        let narrow = legend_line(30);
        let text = line_text(&narrow);
        assert!(text.contains("RUN"), "narrow keeps the words");
        assert!(!text.contains("runs now"), "narrow drops the glosses");
    }

    #[test]
    fn legend_covers_every_outcome_word() {
        let text = line_text(&legend_line(200));
        for outcome in RowOutcome::LEGEND {
            assert!(
                text.contains(outcome.word()),
                "legend lists {}",
                outcome.word()
            );
        }
    }

    #[test]
    fn column_header_collapses_on_narrow_terminals() {
        assert!(line_text(&column_header(120).unwrap()).contains("TOOL"));
        assert!(!line_text(&column_header(70).unwrap()).contains("TOOL"));
        assert!(column_header(40).is_none());
    }
}
