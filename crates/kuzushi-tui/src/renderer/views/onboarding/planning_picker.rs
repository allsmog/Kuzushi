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
    if uses_compact_planning_layout(area) {
        return compact_planning_picker_lines(app, area);
    }
    let lines = expanded_planning_picker_lines(app, area);
    if lines.len() > area.height as usize {
        return compact_planning_picker_lines(app, area);
    }
    lines
}

fn expanded_planning_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    push_phase_header(app, area.width, &mut lines);
    push_target_profile_status(app, &mut lines);
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
    push_prompt_review_hint(app, &mut lines);
    lines.push(enter_summary_line(app, area.width as usize));
    lines.push(planning_controls_line(app, area.width as usize));
    lines
}

fn push_prompt_review_hint(app: &ShellApp, lines: &mut Vec<Line<'static>>) {
    if app.planning_prompt_review_available() {
        lines.push(styled(
            " p Review prompt · opens the selected model-backed instructions",
            theme::accent(),
        ));
    }
}

fn uses_compact_planning_layout(area: Rect) -> bool {
    area.height <= 26 || area.width < 72
}

fn compact_planning_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let width = area.width as usize;
    let mut lines = compact_phase_header_lines(app, area.width);
    if app.engagement.planning_picker().tasks().is_empty() {
        lines.push(muted("(no tasks in this phase)"));
        return lines;
    }
    let available_rows = (area.height as usize)
        .saturating_sub(lines.len() + COMPACT_FIXED_ROWS)
        .max(1);
    let row_budget = available_rows.min(compact_task_row_cap(area));
    lines.extend(compact_task_pane_lines(app, area.width, row_budget));
    lines.push(compact_focus_detail_line(app, width));
    lines.push(enter_summary_line(app, width));
    lines.push(planning_controls_line(app, width));
    lines
}

const COMPACT_FIXED_ROWS: usize = 5;

fn compact_task_row_cap(area: Rect) -> usize {
    if area.width < 72 || area.height <= 18 {
        6
    } else {
        8
    }
}

fn compact_phase_header_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![divider(compact_phase_title(app), width)];
    if let Some(target) = confirmed_target_line(app, width as usize) {
        lines.push(target);
    }
    if !app.engagement.planning_picker().returns_to_setup() {
        push_phase_rail(app, width, &mut lines);
    }
    push_target_profile_status(app, &mut lines);
    let prior = prior_state_banner(app);
    lines.push(fit_spans(prior.spans, width as usize));
    lines
}

fn push_target_profile_status(app: &ShellApp, lines: &mut Vec<Line<'static>>) {
    if app.engagement.planning_picker().profile_pending() {
        lines.push(muted(
            "profiling target… showing conservative tasks; recommendations refresh automatically",
        ));
    }
}

fn compact_phase_title(app: &ShellApp) -> &'static str {
    if app.engagement.planning_picker().returns_to_setup() {
        return "SETUP · MAP PLAN";
    }
    app.engagement
        .current_phase()
        .map(WorkflowPhase::label)
        .unwrap_or("PLAN THE WORKSPACE")
}

fn compact_task_pane_lines(app: &ShellApp, width: u16, row_budget: usize) -> Vec<Line<'static>> {
    let width = (width as usize).max(24);
    let tasks = app.engagement.planning_picker().tasks();
    let range = visible_task_range(
        tasks.len(),
        app.engagement.planning_picker().cursor(),
        row_budget,
    );
    let title = compact_task_pane_title(app, range.start, range.end, tasks.len());
    let border_style = pane_border_style(true);
    let mut lines = vec![border_line(
        "┌",
        &title,
        "┐",
        width,
        border_style,
        pane_title_style(true),
    )];
    lines.extend(range.map(|index| {
        let row = &tasks[index];
        pane_line(
            planning_row_line(app, index, row, width.saturating_sub(4) as u16),
            width,
            border_style,
        )
    }));
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

fn visible_task_range(total: usize, cursor: usize, row_budget: usize) -> std::ops::Range<usize> {
    let visible = row_budget.min(total).max(1);
    let centered = cursor.saturating_sub(visible / 2);
    let start = centered.min(total.saturating_sub(visible));
    start..(start + visible).min(total)
}

fn compact_task_pane_title(app: &ShellApp, start: usize, end: usize, total: usize) -> String {
    let focus = match app.engagement.planning_picker().focus() {
        PickerFocus::OptionsPane => " · OPTION FOCUS",
        PickerFocus::Prompt => " · PROMPT FOCUS",
        PickerFocus::List => " · FOCUS",
    };
    format!(" TASKS {}-{}/{}{} ", start + 1, end, total, focus)
}

fn compact_focus_detail_line(app: &ShellApp, width: usize) -> Line<'static> {
    let text = match app.engagement.planning_picker().focus() {
        PickerFocus::OptionsPane => compact_option_detail(app),
        PickerFocus::Prompt => "Command prompt active; Esc returns to task selection".to_string(),
        PickerFocus::List => compact_task_detail(app),
    };
    styled(&fit(&format!(" {text}"), width), theme::muted())
}

fn compact_task_detail(app: &ShellApp) -> String {
    let Some(row) = app.engagement.planning_picker().current_row() else {
        return "No focused task".to_string();
    };
    if !row.cli_available {
        return format!("Blocked: {}", prerequisite_message(row));
    }
    if row.id.is_inline_action() {
        return compact_inline_action_detail(app, row);
    }
    let disposition = row_disposition(
        row,
        app.engagement.planning_picker().selected(),
        app.engagement.planning_picker().rebuild(),
    );
    let note = planning_row_note(app, row, RowOutcome::from_disposition(disposition));
    format!("Focused: {} · {note}", row.label)
}

fn compact_inline_action_detail(app: &ShellApp, row: &PlanningTaskRow) -> String {
    if planning_row_selected(app, row) {
        "Inline action selected: Enter opens the target-rooted file picker".to_string()
    } else {
        "Inline action unchecked: Space selects it; Enter runs the checked plan".to_string()
    }
}

fn compact_option_detail(app: &ShellApp) -> String {
    if let Some(error) = app.engagement.planning_picker().option_error() {
        return format!("Option: {error}");
    }
    let Some(row) = app.engagement.planning_picker().current_row() else {
        return "No focused option".to_string();
    };
    let Some(tool) = app.registry().resolve_tool(row.tool_name) else {
        return "This inline action has no editable tool options".to_string();
    };
    let Some(spec) = tool
        .options
        .get(app.engagement.planning_picker().option_cursor())
    else {
        return "This step has no declared options".to_string();
    };
    let resolved = app.resolved_input_for_planning_task(row.id).ok();
    let editing = app.engagement.planning_picker().option_edit().is_some();
    let value = option_display_value(app, spec, resolved.as_ref(), editing);
    if editing {
        return format!("Editing {} = {value} · Enter save · Esc cancel", spec.name);
    }
    let source = option_provenance(app, row, spec, resolved.as_ref());
    format!("Option: {} = {value} · {source}", spec.name)
}

fn planning_controls_line(app: &ShellApp, width: usize) -> Line<'static> {
    if app.engagement.planning_picker().option_edit().is_some() {
        let text = if width < 48 {
            " EDITING · type · Enter save · Esc cancel"
        } else {
            " EDITING OPTION  Type value  Enter save  Esc cancel  Backspace edit"
        };
        return styled(&fit(text, width), theme::warn());
    }
    if width < 48 {
        return styled(
            &fit(ultra_compact_planning_controls(app), width),
            theme::muted(),
        );
    }
    let text = match app.engagement.planning_picker().focus() {
        PickerFocus::OptionsPane => " ↑/↓ option  Space cycle  Enter edit  Tab tasks  Esc back",
        PickerFocus::Prompt => " Esc tasks  Enter command  Ctrl+G palette  Ctrl+C exit",
        PickerFocus::List => planning_list_controls(app, width),
    };
    styled(&fit(text, width), theme::muted())
}

fn ultra_compact_planning_controls(app: &ShellApp) -> &'static str {
    if app.engagement.planning_picker().returns_to_setup() {
        return " ↑/↓  Space check  Enter save  Esc setup";
    }
    match app.engagement.planning_picker().focus() {
        PickerFocus::OptionsPane => " ↑/↓  Space cycle  Enter edit  Esc",
        PickerFocus::Prompt => " Esc tasks  Enter submit  Ctrl+C exit",
        PickerFocus::List => match current_inline_action_selected(app) {
            Some(true) => " ↑/↓  Space uncheck  Enter attach  Esc",
            Some(false) => " ↑/↓  Space select  Enter run  Esc",
            None => " ↑/↓  Space check  Enter run  Esc",
        },
    }
}

fn planning_list_controls(app: &ShellApp, width: usize) -> &'static str {
    if app.engagement.planning_picker().returns_to_setup() {
        return setup_planning_controls(width);
    }
    if let Some(selected) = current_inline_action_selected(app) {
        return inline_planning_controls(selected);
    }
    default_planning_controls(app, width)
}

fn default_planning_controls(app: &ShellApp, width: usize) -> &'static str {
    if width < 76 {
        return " ↑/↓ move  Space check  Tab pane  Enter run  Esc exit";
    }
    if app.planning_prompt_review_available() {
        " ↑/↓ move  Space check  p Review prompt  Tab pane  Enter run  Esc exit"
    } else {
        " ↑/↓ move  Space check  Tab pane  h/l phase  Enter run  Esc exit"
    }
}

fn setup_planning_controls(width: usize) -> &'static str {
    if width < 76 {
        " ↑/↓ move  Space check  Enter save  Esc setup"
    } else {
        " ↑/↓ move  Space check  p Review prompt  Tab pane  Enter save to Setup  Esc return"
    }
}

fn inline_planning_controls(selected: bool) -> &'static str {
    if selected {
        " ↑/↓ move  Space uncheck  Enter attach file  Esc exit"
    } else {
        " ↑/↓ move  Space select attach  Enter run checked  Esc exit"
    }
}

fn current_inline_action_selected(app: &ShellApp) -> Option<bool> {
    let row = app.engagement.planning_picker().current_row()?;
    row.id
        .is_inline_action()
        .then(|| planning_row_selected(app, row))
}

fn planning_row_selected(app: &ShellApp, row: &PlanningTaskRow) -> bool {
    app.engagement
        .planning_picker()
        .selected()
        .contains(&row.id)
}

/// Announce the current phase and its intent.
fn push_phase_header(app: &ShellApp, width: u16, lines: &mut Vec<Line<'static>>) {
    if app.engagement.planning_picker().returns_to_setup() {
        push_setup_plan_header(app, width, lines);
        return;
    }
    match app.engagement.current_phase() {
        Some(phase) => push_active_phase_header(app, phase, width, lines),
        None => push_unphased_plan_header(app, width, lines),
    }
}

fn push_setup_plan_header(app: &ShellApp, width: u16, lines: &mut Vec<Line<'static>>) {
    push_header_identity(app, "SETUP · MAP PLAN", width, lines);
    lines.push(muted(
        "Choose Map tasks. Model and credential blockers are evaluated back on Setup.",
    ));
}

fn push_active_phase_header(
    app: &ShellApp,
    phase: WorkflowPhase,
    width: u16,
    lines: &mut Vec<Line<'static>>,
) {
    push_header_identity(app, phase.label(), width, lines);
    push_phase_rail(app, width, lines);
    lines.push(muted(&phase_position_line(app, phase)));
}

/// One phase vocabulary on screen: when the planner is browsing a phase
/// other than the ledger-derived current one, say so explicitly instead of
/// letting the title, rail, and status line contradict each other.
fn phase_position_line(app: &ShellApp, phase: WorkflowPhase) -> String {
    let base = format!(
        "phase {} of {} — {}",
        phase.position(),
        WorkflowPhase::ORDER.len(),
        phase.intent()
    );
    let Some(current) = journey_model(app).map(|journey| journey.current) else {
        return base;
    };
    if current == phase {
        return base;
    }
    format!(
        "planning {} · engagement is in {} — Enter runs {} steps",
        phase.label(),
        current.title(),
        phase.label()
    )
}

fn push_unphased_plan_header(app: &ShellApp, width: u16, lines: &mut Vec<Line<'static>>) {
    push_header_identity(app, "PLAN THE WORKSPACE", width, lines);
    lines.push(muted(
        "Select tasks. Dependencies auto-toggle. Steps run in order.",
    ));
}

fn push_header_identity(app: &ShellApp, title: &str, width: u16, lines: &mut Vec<Line<'static>>) {
    lines.push(divider(title, width));
    if let Some(target) = confirmed_target_line(app, width as usize) {
        lines.push(target);
    }
    lines.push(blank());
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
        WorkflowPhase::Map => "Map",
        WorkflowPhase::Scan => "Scan",
        WorkflowPhase::Review => "Review",
        WorkflowPhase::Prove => "Prove",
        WorkflowPhase::Fix => "Fix",
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
        .borrow()
        .cached_map_artifacts_built(app.target());
    let map_artifacts_built = matches!(map_artifacts_built, crate::app::ViewDataState::Ready(true));
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
        Span::styled(fresh_pass_hint(app), theme::muted()),
    ])
}

/// The fresh-pass affordance names the phase this picker is actually on;
/// the old static "phase map" clause claimed a Map reset on every phase.
fn fresh_pass_hint(app: &ShellApp) -> String {
    let phase = app
        .engagement
        .current_phase()
        .map(|phase| phase.label().to_ascii_lowercase())
        .unwrap_or_else(|| "map".to_string());
    format!(" · next fresh restarts the pass · phase {phase} reopens this planner")
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
    spans.iter().map(|span| display_width(&span.content)).sum()
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
        .or_else(|| model_readiness_note(app, row))
        .unwrap_or_else(|| outcome_row_note(app, row, outcome))
}

fn blocked_row_note(row: &PlanningTaskRow, outcome: RowOutcome) -> Option<String> {
    (outcome == RowOutcome::Blocked).then(|| format!("blocked — {}", prerequisite_message(row)))
}

fn prerequisite_message(row: &PlanningTaskRow) -> String {
    if let Some(reason) = row.blocker.as_deref() {
        return reason.to_string();
    }
    row.required_cli
        .map(|cli| format!("install `{cli}` on PATH"))
        .unwrap_or_else(|| "required prerequisite is unavailable".to_string())
}

fn cached_row_note(row: &PlanningTaskRow, outcome: RowOutcome) -> Option<String> {
    if !matches!(row.artifact_state, PlanningArtifactState::Cached) {
        return None;
    }
    let cached = match row.cached_detail.as_deref() {
        Some(detail) => format!("cached · {detail}"),
        None => "cached".to_string(),
    };
    if let Some(cli) = row.required_cli.filter(|_| !row.cli_available) {
        return Some(format!("{cached} — rebuild needs {cli}"));
    }
    (outcome == RowOutcome::Reuse).then(|| format!("{cached} — press g to rebuild"))
}

fn model_readiness_note(app: &ShellApp, row: &PlanningTaskRow) -> Option<String> {
    model_readiness_message(
        row.model_backed,
        app.config().model.is_some(),
        app.configured_model_auth_ready(),
    )
}

fn model_readiness_message(
    model_backed: bool,
    model_configured: bool,
    provider_auth_ready: bool,
) -> Option<String> {
    if !model_backed {
        return None;
    }
    if !model_configured {
        return Some("needs model — run /model first".to_string());
    }
    (!provider_auth_ready).then(|| "needs credentials — open auth".to_string())
}

fn outcome_row_note(app: &ShellApp, row: &PlanningTaskRow, outcome: RowOutcome) -> String {
    if let Some(note) = last_attempt_note(row) {
        return with_cost(row, &note);
    }
    match outcome {
        RowOutcome::Run if app.engagement.planning_picker().rebuild().contains(&row.id) => {
            with_cost(row, "rebuild (overwrites cache)")
        }
        RowOutcome::Run | RowOutcome::Skip => with_cost(row, artifact_reason(row)),
        RowOutcome::Reuse | RowOutcome::Blocked => unreachable!("handled above"),
    }
}

/// Honest ledger note: a resumable failed attempt continues instead of
/// restarting; blocked and completed attempts remain distinct.
fn last_attempt_note(row: &PlanningTaskRow) -> Option<String> {
    use crate::app::LastAttempt;
    match row.last_attempt.as_ref()? {
        LastAttempt::Failed {
            resumable: true,
            resume_from: Some(stage),
        } => Some(format!("continue · resumes at {stage}")),
        LastAttempt::Failed {
            resumable: true,
            resume_from: None,
        } => Some("continue from checkpoint".to_string()),
        LastAttempt::Failed { .. } => Some("failed last pass".to_string()),
        LastAttempt::Blocked => Some("blocked last pass".to_string()),
        LastAttempt::Completed if matches!(row.artifact_state, PlanningArtifactState::Action) => {
            Some("done this pass".to_string())
        }
        LastAttempt::Completed => None,
    }
}

fn artifact_reason(row: &PlanningTaskRow) -> &'static str {
    match row.artifact_state {
        PlanningArtifactState::Cached => "cached",
        PlanningArtifactState::Missing => "not built yet",
        PlanningArtifactState::Invalid => "cached but invalid",
        PlanningArtifactState::Action => "inline action — Space selects",
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
    if !row.cli_available {
        return unavailable_task_pane_lines(&title, row, width, border_style);
    }
    if row.id.is_inline_action() {
        return inline_action_pane_lines(app, row, &title, width, border_style);
    }
    let Some(tool) = app.registry().resolve_tool(row.tool_name) else {
        return bordered_message(&title, "options unavailable for this step", width);
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

fn unavailable_task_pane_lines(
    title: &str,
    row: &PlanningTaskRow,
    width: usize,
    border_style: Style,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        border_line("┌", title, "┐", width, border_style, theme::label()),
        pane_body_line(
            "blocked — prerequisite missing",
            width,
            theme::danger(),
            border_style,
        ),
    ];
    lines.extend(
        wrap_text(&prerequisite_message(row), width.saturating_sub(4).max(1))
            .into_iter()
            .map(|line| pane_body_line(&line, width, theme::primary(), border_style)),
    );
    lines.push(pane_body_line(
        "Space retries after the prerequisite is available",
        width,
        theme::muted(),
        border_style,
    ));
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

fn inline_action_pane_lines(
    app: &ShellApp,
    row: &PlanningTaskRow,
    title: &str,
    width: usize,
    border_style: Style,
) -> Vec<Line<'static>> {
    let (state, action) = if planning_row_selected(app, row) {
        (
            "selected inline action — no module runs",
            "Enter opens the target file picker",
        )
    } else {
        (
            "unchecked inline action — no module runs",
            "Space selects; Enter runs checked plan",
        )
    };
    vec![
        border_line("┌", title, "┐", width, border_style, theme::label()),
        pane_body_line(state, width, theme::accent(), border_style),
        pane_body_line(action, width, theme::primary(), border_style),
        pane_body_line(
            "attachments stay rooted to this target",
            width,
            theme::muted(),
            border_style,
        ),
        border_line("└", "", "┘", width, border_style, theme::label()),
    ]
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
        return format!("EDIT:{draft}_");
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
    let fill = inner_width.saturating_sub(display_width(&title));
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
fn enter_summary_line(app: &ShellApp, width: usize) -> Line<'static> {
    if app.engagement.planning_picker().returns_to_setup() {
        let selected = app.engagement.planning_picker().selected().len();
        return styled(
            &fit(
                &format!(" Enter saves {selected} selected Map task(s) and returns to Setup"),
                width,
            ),
            theme::success().add_modifier(Modifier::BOLD),
        );
    }
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
    styled(&format!(" {}", enter_summary_text(plan, width)), style)
}

fn enter_summary_text(plan: crate::ui_view_models::EnterPlan, width: usize) -> String {
    let full = plan.summary_line();
    if display_width(&full) < width {
        return full;
    }
    compact_enter_summary(plan)
}

fn compact_enter_summary(plan: crate::ui_view_models::EnterPlan) -> String {
    if plan.run == 0 {
        return compact_nothing_runs_summary(plan);
    }
    compact_running_summary(plan)
}

fn compact_running_summary(plan: crate::ui_view_models::EnterPlan) -> String {
    let clauses = [
        Some(format!("run {}", plan.run)),
        compact_count_clause("reuse", plan.reuse),
        compact_count_clause("skip", plan.skip),
        compact_count_clause("blocked", plan.blocked),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    format!("Enter: {}", clauses.join(" · "))
}

fn compact_count_clause(label: &str, count: usize) -> Option<String> {
    (count > 0).then(|| format!("{label} {count}"))
}

fn compact_nothing_runs_summary(plan: crate::ui_view_models::EnterPlan) -> String {
    if plan.reuse > 0 {
        return format!(
            "Enter: runs nothing · reuse {} cached · g rebuild",
            plan.reuse
        );
    }
    "Enter: runs nothing · no tasks checked · skips phase".to_string()
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
    use kuzushi_core::{V2Config, WorkspaceTarget};

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn rendered_planning_lines(width: u16, height: u16) -> String {
        let target_dir = tempfile::tempdir().expect("temp target");
        let target = WorkspaceTarget::new(target_dir.path()).expect("workspace target");
        let mut app = ShellApp::new(V2Config::default(), Some(&target));
        app.open_phase_picker(crate::app::WorkflowPhase::Map);
        planning_picker_lines(&app, Rect::new(0, 0, width, height))
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_essential_planning_controls(rendered: &str) {
        for control in [
            "↑/↓ move",
            "Space check",
            "Tab pane",
            "h/l phase",
            "Enter run",
            "Esc exit",
        ] {
            assert!(
                rendered.contains(control),
                "missing {control:?}:\n{rendered}"
            );
        }
    }

    #[test]
    fn pending_target_profile_is_visible_in_the_picker() {
        let rendered = rendered_planning_lines(120, 40);

        assert!(rendered.contains("profiling target"), "{rendered}");
        assert!(rendered.contains("conservative tasks"), "{rendered}");
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

    #[test]
    fn compact_task_window_tracks_the_cursor_without_losing_ends() {
        assert_eq!(visible_task_range(9, 0, 6), 0..6);
        assert_eq!(visible_task_range(9, 5, 6), 2..8);
        assert_eq!(visible_task_range(9, 8, 6), 3..9);
    }

    #[test]
    fn compact_enter_summary_keeps_every_consequential_bucket() {
        let plan = crate::ui_view_models::EnterPlan {
            run: 5,
            reuse: 2,
            skip: 3,
            blocked: 1,
        };

        let summary = enter_summary_text(plan, 60);

        assert_eq!(summary, "Enter: run 5 · reuse 2 · skip 3 · blocked 1");
        assert!(display_width(&summary) < 60);
    }

    #[test]
    fn full_enter_summary_requires_room_for_its_leading_space() {
        let plan = crate::ui_view_models::EnterPlan {
            run: 2,
            reuse: 1,
            skip: 0,
            blocked: 0,
        };
        let full = plan.summary_line();

        assert_eq!(enter_summary_text(plan, display_width(&full) + 1), full);
        assert_ne!(enter_summary_text(plan, display_width(&full)), full);
    }

    #[test]
    fn model_backed_row_distinguishes_missing_model_from_missing_auth() {
        assert_eq!(
            model_readiness_message(true, false, false).as_deref(),
            Some("needs model — run /model first")
        );
        assert_eq!(
            model_readiness_message(true, true, false).as_deref(),
            Some("needs credentials — open auth")
        );
        assert_eq!(model_readiness_message(true, true, true), None);
        assert_eq!(model_readiness_message(false, true, false), None);
    }

    #[test]
    fn blocked_last_attempt_is_not_presented_as_completed() {
        let target = tempfile::tempdir().unwrap();
        let mut row =
            PlanningTaskRow::for_task(crate::app::PlanningTaskId::ScanAgenticSast, target.path());
        row.last_attempt = Some(crate::app::LastAttempt::Blocked);

        assert_eq!(
            last_attempt_note(&row).as_deref(),
            Some("blocked last pass")
        );
    }

    #[test]
    fn wide_planning_keeps_essential_controls_at_120x40() {
        assert_essential_planning_controls(&rendered_planning_lines(120, 40));
    }

    #[test]
    fn wide_planning_keeps_essential_controls_at_100x30() {
        assert_essential_planning_controls(&rendered_planning_lines(100, 30));
    }
}
