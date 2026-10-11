use super::*;
use crate::app::{
    format_option_value, option_edit_hint, option_input_kind, option_is_operator_editable,
    row_disposition, PickerFocus, PlanningArtifactState, PlanningTaskRow, WorkflowPhase,
};
use crate::ui_view_models::{
    enter_plan, format_relative_age, journey_model, latest_cached_modified, option_display_name,
    workspace_history, JourneyPhaseState, JourneyPhaseStatus, JourneyPhaseTone, RowOutcome,
    WorkspaceHistory,
};
use kuzushi_core::modules::OptionSpec;
use kuzushi_core::OptionScope;
use serde_json::Value;
use std::time::SystemTime;

mod option_editor;
pub(crate) use option_editor::planning_option_error_scroll;

pub(crate) fn planning_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if let Some(edit) = app.engagement.planning_picker().option_edit() {
        return option_editor::option_editor_lines(app, edit, area);
    }
    match planning_layout_mode(area) {
        PlanningLayoutMode::Compact => compact_planning_picker_lines(app, area),
        mode => expanded_planning_picker_lines(app, area, mode),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanningLayoutMode {
    Compact,
    Stacked,
    MasterDetail,
}

fn planning_layout_mode(area: Rect) -> PlanningLayoutMode {
    if area.height <= 26 || area.width < 72 {
        return PlanningLayoutMode::Compact;
    }
    if area.width as usize >= MASTER_DETAIL_WIDTH {
        return PlanningLayoutMode::MasterDetail;
    }
    PlanningLayoutMode::Stacked
}

fn expanded_planning_picker_lines(
    app: &ShellApp,
    area: Rect,
    mode: PlanningLayoutMode,
) -> Vec<Line<'static>> {
    let mut lines = expanded_planning_header_lines(app, area.width);
    if app.engagement.planning_picker().tasks().is_empty() {
        lines.push(muted("(no tasks in this phase)"));
        return lines;
    }
    let footer = expanded_planning_footer_lines(app, area.width as usize);
    let pane_budget = (area.height as usize).saturating_sub(lines.len() + footer.len());
    lines.extend(expanded_planning_panes(app, area.width, pane_budget, mode));
    lines.extend(footer);
    lines
}

fn expanded_planning_header_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    push_phase_header(app, width, &mut lines);
    push_target_profile_status(app, &mut lines);
    lines.push(blank());
    lines.push(prior_state_banner(app));
    lines.push(blank());
    lines.push(legend_line(width));
    lines.push(blank());
    lines
}

fn expanded_planning_footer_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    vec![
        prompt_review_hint_line(app),
        enter_summary_line(app, width),
        planning_controls_line(app, width),
    ]
}

fn prompt_review_hint_line(app: &ShellApp) -> Line<'static> {
    if app.planning_prompt_review_available() {
        return styled(" Prompt review is available from Setup", theme::accent());
    }
    blank()
}

fn expanded_planning_panes(
    app: &ShellApp,
    width: u16,
    height: usize,
    mode: PlanningLayoutMode,
) -> Vec<Line<'static>> {
    match mode {
        PlanningLayoutMode::MasterDetail => master_detail_rows(app, width, height),
        PlanningLayoutMode::Stacked | PlanningLayoutMode::Compact => {
            stacked_planning_panes(app, width, height)
        }
    }
}

fn stacked_planning_panes(app: &ShellApp, width: u16, height: usize) -> Vec<Line<'static>> {
    let content_height = height.saturating_sub(1);
    let (task_height, option_height) = stacked_pane_heights(
        app.engagement.planning_picker().tasks().len(),
        content_height,
    );
    let mut lines = task_list_pane_lines(app, width, task_height);
    lines.push(blank());
    lines.extend(planning_options_pane_lines(
        app,
        width as usize,
        option_height,
    ));
    lines
}

fn stacked_pane_heights(task_count: usize, content_height: usize) -> (usize, usize) {
    if content_height < 12 {
        let task_height = content_height / 2;
        return (task_height, content_height.saturating_sub(task_height));
    }
    let task_needed = task_count.saturating_add(3);
    let task_max = content_height.saturating_sub(10);
    let task_height = task_needed.clamp(4, task_max.max(4));
    (task_height, content_height.saturating_sub(task_height))
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

/// Name the phase these rows belong to, exactly as the expanded header does.
/// The compact divider is the only phase vocabulary a small terminal gets, so
/// it must read the picker's own phase and never the engagement's: completing a
/// phase from Run Focus advances the ledger without rebuilding the checklist.
fn compact_phase_title(app: &ShellApp) -> &'static str {
    if app.engagement.planning_picker().returns_to_setup() {
        return "SETUP · MAP PLAN";
    }
    app.engagement
        .planning_picker()
        .phase()
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
        .iter()
        .filter(|spec| option_is_operator_editable(spec))
        .nth(app.engagement.planning_picker().option_cursor())
    else {
        return "This step has no declared options".to_string();
    };
    let resolved = app.resolved_input_for_planning_task(row.id).ok();
    let value = option_display_value(spec, resolved.as_ref());
    let source = option_provenance(app, row, spec, resolved.as_ref());
    format!(
        "Option · {} = {value} · {source} · {} · {}",
        option_display_name(&spec.name),
        option_input_kind(spec),
        option_edit_hint(spec)
    )
}

fn planning_controls_line(app: &ShellApp, width: usize) -> Line<'static> {
    if width < 48 {
        return styled(
            &fit(ultra_compact_planning_controls(app), width),
            theme::muted(),
        );
    }
    let text = match app.engagement.planning_picker().focus() {
        PickerFocus::OptionsPane => {
            " ↑/↓ option  Space cycle  Enter edit  Tab tasks  type cmd  Ctrl+S persist  Esc back"
        }
        PickerFocus::Prompt => " Esc tasks  Enter command  Ctrl+G palette  Ctrl+C exit",
        PickerFocus::List => planning_list_controls(app, width),
    };
    styled(&fit(text, width), theme::muted())
}

fn ultra_compact_planning_controls(app: &ShellApp) -> &'static str {
    if app.engagement.planning_picker().returns_to_setup() {
        return " ↑/↓  Space outcome  Enter save  Esc setup";
    }
    match app.engagement.planning_picker().focus() {
        PickerFocus::OptionsPane => " ↑/↓  Space cycle  Enter edit  Esc",
        PickerFocus::Prompt => " Esc tasks  Enter submit  Ctrl+C exit",
        PickerFocus::List => match current_inline_action_selected(app) {
            Some(true) => " ↑/↓  Space uncheck  Enter attach  Esc",
            Some(false) => " ↑/↓  Space select  Enter run  Esc",
            None => " ↑/↓  Space outcome  Enter run  Esc",
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

fn default_planning_controls(_app: &ShellApp, width: usize) -> &'static str {
    if width < 92 {
        return " ↑/↓ move  Space outcome  Tab  Enter run  type cmd  Esc exit";
    }
    " ↑/↓ move  Space outcome  Tab pane  ←/→ phase  Enter run  type command  Esc exit"
}

fn setup_planning_controls(width: usize) -> &'static str {
    if width < 76 {
        " ↑/↓ move  Space outcome  Tab  Enter save  type cmd  Esc return"
    } else {
        " ↑/↓ move  Space outcome  Tab pane  Enter save  type command  Esc return"
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

/// Announce the phase these rows belong to and its intent. The title names the
/// picker's own phase, never the engagement's: completing a phase from Run
/// Focus advances the engagement without rebuilding the checklist, and a title
/// taken from the ledger would then head another phase's task rows.
fn push_phase_header(app: &ShellApp, width: u16, lines: &mut Vec<Line<'static>>) {
    if app.engagement.planning_picker().returns_to_setup() {
        push_setup_plan_header(app, width, lines);
        return;
    }
    match app.engagement.planning_picker().phase() {
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
        "{} — {}",
        crate::ui_view_models::journey_phase_segment(phase),
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
        Span::styled("‹← ", theme::accent()),
        Span::styled("phase ", theme::muted()),
    ];
    for (idx, phase) in phases.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::styled("  ", theme::subtle()));
        }
        push_phase_segment(&mut spans, idx, phase);
    }
    spans.push(Span::styled(" →›", theme::accent()));
    fit_spans(spans, width)
}

fn push_phase_segment(spans: &mut Vec<Span<'static>>, index: usize, phase: &JourneyPhaseStatus) {
    let label = phase.phase_label.trim();
    let text = format!("{} {label} {}", index + 1, phase.navigation_symbol());
    if phase.state == JourneyPhaseState::Current {
        spans.push(Span::styled("[", theme::warn()));
        spans.push(Span::styled(text, phase_tone_style(phase.tone)));
        spans.push(Span::styled("]", theme::warn()));
    } else {
        spans.push(Span::styled(text, phase_tone_style(phase.tone)));
    }
}

fn fallback_phase_rail_line(current: WorkflowPhase, width: usize) -> Line<'static> {
    let statuses: Vec<JourneyPhaseStatus> = WorkflowPhase::INVESTIGATION_ORDER
        .iter()
        .map(|&phase| JourneyPhaseStatus {
            phase,
            state: if phase == current {
                JourneyPhaseState::Current
            } else {
                JourneyPhaseState::Pending
            },
            access: if phase == current {
                crate::ui_view_models::JourneyPhaseAccess::Available
            } else {
                crate::ui_view_models::JourneyPhaseAccess::Locked {
                    reason: "complete the current phase first",
                }
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
    let prior_attempt = WorkflowPhase::ORDER
        .iter()
        .any(|phase| app.engagement.has_phase_attempt_for_target(*phase));
    match workspace_history(
        app.engagement.planning_picker().tasks(),
        app.findings().len(),
        map_artifacts_built,
        prior_attempt,
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
                "Revisiting · Space cycles cached work through reuse, run, and skip".to_string(),
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
        Span::styled(fresh_pass_hint(), theme::muted()),
    ])
}

fn fresh_pass_hint() -> &'static str {
    " · Space: reuse → run → skip"
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
            "    {:<8} {:<30} {:<22} {}",
            "OUTCOME", "TASK", "TOOL", "WHY"
        )
    } else if w >= MEDIUM {
        format!("    {:<8} {:<28} {}", "OUTCOME", "TASK", "WHY")
    } else {
        return None;
    };
    Some(styled(&fit(&body, w), theme::subtle()))
}

const WIDE: usize = 88;
const MEDIUM: usize = 60;
const MASTER_DETAIL_WIDTH: usize = 118;

fn master_detail_rows(app: &ShellApp, width: u16, height: usize) -> Vec<Line<'static>> {
    let w = width as usize;
    let detail_width = (w / 3).clamp(38, 52);
    let list_width = w.saturating_sub(detail_width + 2);
    let left = task_list_pane_lines(app, list_width as u16, height);
    let right = planning_options_pane_lines(app, detail_width, height);
    (0..height)
        .map(|idx| join_pane_lines(left.get(idx).cloned(), right.get(idx).cloned(), list_width))
        .collect()
}

fn task_list_pane_lines(app: &ShellApp, width: u16, height: usize) -> Vec<Line<'static>> {
    let width = (width as usize).max(24);
    let focused = app.engagement.planning_picker().focus() == PickerFocus::List;
    let border_style = pane_border_style(focused);
    let body_height = height.saturating_sub(2);
    let header = column_header(width.saturating_sub(4) as u16).filter(|_| body_height > 1);
    let row_budget = body_height.saturating_sub(usize::from(header.is_some()));
    let tasks = app.engagement.planning_picker().tasks();
    let range = visible_task_range(
        tasks.len(),
        app.engagement.planning_picker().cursor(),
        row_budget,
    );
    let title = task_pane_title(app, range.start, range.end, tasks.len(), focused);
    let mut lines = vec![border_line(
        "┌",
        &title,
        "┐",
        width,
        border_style,
        pane_title_style(focused),
    )];
    lines.extend(
        header
            .into_iter()
            .map(|line| pane_line(line, width, border_style)),
    );
    lines.extend(range.map(|index| {
        pane_line(
            planning_row_line(app, index, &tasks[index], width.saturating_sub(4) as u16),
            width,
            border_style,
        )
    }));
    finish_bordered_pane(lines, width, height, border_style)
}

fn task_pane_title(
    app: &ShellApp,
    start: usize,
    end: usize,
    total: usize,
    focused: bool,
) -> String {
    let range = if end.saturating_sub(start) < total {
        format!(" {}-{end}/{total}", start + 1)
    } else {
        String::new()
    };
    let focused = focused && !app.engagement.planning_picker().tasks().is_empty();
    pane_title(&format!(" TASKS{range} "), focused)
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
            "  {marker} {outcome:<8} {label:<30} {tool_name:<22} {note}",
            outcome = outcome.word(),
        );
    }
    if width >= MEDIUM {
        return format!(
            "  {marker} {outcome:<8} {label:<28} {note}",
            outcome = outcome.word(),
        );
    }
    format!("  {marker} {outcome:<8} {label}", outcome = outcome.word())
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
        .or_else(|| unresolved_input_note(app, row))
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
    // This note wins over `last_attempt_note`, so an artifact a partial pass
    // left behind would otherwise be offered as a complete cache. Tools whose
    // partial result persists its document (`threat-model:build`) reach here.
    let cached = match row.last_attempt {
        Some(crate::app::LastAttempt::Partial { .. }) => format!("{cached} (partial)"),
        _ => cached,
    };
    if let Some(cli) = row.required_cli.filter(|_| !row.cli_available) {
        return Some(format!("{cached} — rebuild needs {cli}"));
    }
    (outcome == RowOutcome::Reuse).then(|| format!("{cached} · Space runs fresh"))
}

/// A task whose input cannot be prepared has no model to check yet; naming
/// the input problem keeps it from reading as "needs model" when one is set.
fn unresolved_input_note(app: &ShellApp, row: &PlanningTaskRow) -> Option<String> {
    if row.id.is_inline_action() {
        return None;
    }
    let input = match row.id {
        crate::app::PlanningTaskId::ImportThreatModel => app.validated_context_import_input(),
        _ => app.resolved_input_for_planning_task(row.id),
    };
    let error = input.err()?;
    Some(unresolved_input_message(row.tool_name, &error.to_string()))
}

/// The row already names its tool, so the reason drops that prefix.
fn unresolved_input_message(tool: &str, error: &str) -> String {
    let first_line = error.lines().next().unwrap_or_default();
    let reason = first_line.split("; ").next().unwrap_or(first_line).trim();
    let reason = reason.strip_prefix(tool).map_or(reason, str::trim_start);
    format!("needs input: {reason}")
}

fn model_readiness_note(app: &ShellApp, row: &PlanningTaskRow) -> Option<String> {
    let model = app.planning_task_model(row.id);
    let auth_ready = model
        .as_deref()
        .and_then(|model| model.split_once(':').map(|(provider, _)| provider))
        .is_some_and(|provider| app.provider_auth_ready_for(provider));
    model_readiness_message(
        app.planning_task_model_backed(row.id),
        model.is_some(),
        auth_ready,
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
        return with_cost(app, row, &note);
    }
    match outcome {
        RowOutcome::Run if app.engagement.planning_picker().rebuild().contains(&row.id) => {
            with_cost(app, row, "runs fresh")
        }
        RowOutcome::Run | RowOutcome::Skip => with_cost(app, row, artifact_reason(row)),
        RowOutcome::Reuse | RowOutcome::Blocked => unreachable!("handled above"),
    }
}

/// Honest ledger note: a resumable failed attempt continues instead of
/// restarting; blocked, partial, and completed attempts remain distinct. A
/// partial pass produced a disclosed incomplete result, so it never borrows
/// the wording of a pass that produced nothing.
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
        LastAttempt::Failed { .. } => Some("retry from start · failed last pass".to_string()),
        LastAttempt::Partial {
            resumable: true,
            resume_from: Some(stage),
        } => Some(format!("continue · partial · resumes at {stage}")),
        LastAttempt::Partial {
            resumable: true,
            resume_from: None,
        } => Some("continue from checkpoint · partial".to_string()),
        LastAttempt::Partial { .. } => Some("retry from start · partial last pass".to_string()),
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
        PlanningArtifactState::Action => "fresh action · Space selects",
    }
}

fn with_cost(app: &ShellApp, row: &PlanningTaskRow, base: &str) -> String {
    let mut parts = vec![base.to_string()];
    if app.planning_task_model_backed(row.id) {
        parts.push("model-backed".to_string());
    }
    if let Some(cli) = row.required_cli.filter(|_| row.cli_available) {
        parts.push(format!("{cli} ready"));
    }
    parts.join(" · ")
}

fn planning_options_pane_lines(app: &ShellApp, width: usize, height: usize) -> Vec<Line<'static>> {
    let width = width.max(24);
    let Some(row) = app.engagement.planning_picker().current_row() else {
        return bordered_message("options", "no focused step", width, height);
    };
    let focused = app.engagement.planning_picker().focus() == PickerFocus::OptionsPane;
    let border_style = pane_border_style(focused);
    let title = option_pane_title(row.tool_name, focused);
    if !row.cli_available {
        return unavailable_task_pane_lines(&title, row, width, height, border_style);
    }
    if row.id.is_inline_action() {
        return inline_action_pane_lines(app, row, &title, width, height, border_style);
    }
    let Some(tool) = app.registry().resolve_tool(row.tool_name) else {
        return bordered_message(&title, "options unavailable for this step", width, height);
    };
    let mut lines = option_pane_header(&title, focused, border_style, width);
    let options = tool
        .options
        .iter()
        .filter(|spec| option_is_operator_editable(spec))
        .cloned()
        .collect::<Vec<_>>();
    let body_height = height.saturating_sub(2);
    lines.extend(option_pane_body_lines(
        app,
        row,
        &options,
        width,
        body_height,
        border_style,
    ));
    finish_bordered_pane(lines, width, height, border_style)
}

fn option_pane_title(tool_name: &str, focused: bool) -> String {
    if focused {
        format!(" OPTION FOCUS · {tool_name} ")
    } else {
        format!(" OPTIONS · {tool_name} ")
    }
}

fn unavailable_task_pane_lines(
    title: &str,
    row: &PlanningTaskRow,
    width: usize,
    height: usize,
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
    finish_bordered_pane(lines, width, height, border_style)
}

fn inline_action_pane_lines(
    app: &ShellApp,
    row: &PlanningTaskRow,
    title: &str,
    width: usize,
    height: usize,
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
    let lines = vec![
        border_line("┌", title, "┐", width, border_style, theme::label()),
        pane_body_line(state, width, theme::accent(), border_style),
        pane_body_line(action, width, theme::primary(), border_style),
        pane_body_line(
            "attachments stay rooted to this target",
            width,
            theme::muted(),
            border_style,
        ),
    ];
    finish_bordered_pane(lines, width, height, border_style)
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

fn option_pane_body_lines(
    app: &ShellApp,
    row: &PlanningTaskRow,
    options: &[OptionSpec],
    width: usize,
    height: usize,
    border_style: Style,
) -> Vec<Line<'static>> {
    if options.is_empty() {
        return vec![pane_body_line(
            "no editable options · workflow-supplied settings stay with the workflow",
            width,
            theme::muted(),
            border_style,
        )];
    }
    if height < 10 {
        return compact_option_pane_body_lines(app, row, options, width, height, border_style);
    }
    rich_option_pane_body_lines(app, row, options, width, height, border_style)
}

fn compact_option_pane_body_lines(
    app: &ShellApp,
    row: &PlanningTaskRow,
    options: &[OptionSpec],
    width: usize,
    height: usize,
    border_style: Style,
) -> Vec<Line<'static>> {
    let index = selected_option_index(app, options);
    let spec = &options[index];
    let resolved = app.resolved_input_for_planning_task(row.id).ok();
    let mut lines = vec![option_pane_row(
        app,
        row,
        spec,
        index,
        resolved.as_ref(),
        width,
    )];
    lines.push(pane_body_line("", width, theme::muted(), border_style));
    let detail = compact_selected_option_detail(app, row, spec, resolved.as_ref());
    lines.push(pane_body_line(
        &detail,
        width,
        theme::primary(),
        border_style,
    ));
    lines.push(pane_body_line(
        &option_edit_hint(spec),
        width,
        theme::accent(),
        border_style,
    ));
    append_option_error(&mut lines, app, width, border_style);
    lines.truncate(height);
    lines
}

fn rich_option_pane_body_lines(
    app: &ShellApp,
    row: &PlanningTaskRow,
    options: &[OptionSpec],
    width: usize,
    height: usize,
    border_style: Style,
) -> Vec<Line<'static>> {
    let error_rows = usize::from(app.engagement.planning_picker().option_error().is_some());
    let budgets = option_pane_budgets(height.saturating_sub(error_rows));
    let resolved = app.resolved_input_for_planning_task(row.id).ok();
    let index = selected_option_index(app, options);
    let mut lines = visible_option_rows(app, row, options, resolved.as_ref(), width, budgets.list);
    lines.push(pane_body_line("", width, theme::muted(), border_style));
    append_selected_option_detail(
        &mut lines,
        app,
        row,
        &options[index],
        index,
        options.len(),
        resolved.as_ref(),
        width,
        budgets.detail,
        border_style,
    );
    append_option_error(&mut lines, app, width, border_style);
    lines.truncate(height);
    lines
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OptionPaneBudgets {
    list: usize,
    detail: usize,
}

fn option_pane_budgets(height: usize) -> OptionPaneBudgets {
    let list = if height >= 16 { 4 } else { 3 };
    OptionPaneBudgets {
        list,
        detail: height.saturating_sub(list + 2),
    }
}

fn selected_option_index(app: &ShellApp, options: &[OptionSpec]) -> usize {
    app.engagement
        .planning_picker()
        .option_cursor()
        .min(options.len().saturating_sub(1))
}

fn visible_option_rows(
    app: &ShellApp,
    row: &PlanningTaskRow,
    options: &[OptionSpec],
    resolved: Option<&Value>,
    width: usize,
    budget: usize,
) -> Vec<Line<'static>> {
    visible_task_range(options.len(), selected_option_index(app, options), budget)
        .map(|index| option_pane_row(app, row, &options[index], index, resolved, width))
        .collect()
}

fn append_option_error(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    width: usize,
    border_style: Style,
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

fn bordered_message(title: &str, message: &str, width: usize, height: usize) -> Vec<Line<'static>> {
    let border_style = theme::subtle();
    finish_bordered_pane(
        vec![
            border_line("┌", title, "┐", width, border_style, theme::label()),
            pane_body_line(message, width, theme::muted(), border_style),
        ],
        width,
        height,
        border_style,
    )
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
    let marker = if selected { ">" } else { " " };
    let value = option_display_value(spec, resolved);
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
    _body_width: usize,
) -> String {
    format!("{marker} {name} = {value} · {provenance}")
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
    format!(
        "{}{}",
        option_display_name(&spec.name),
        option_status_badges(app, row, spec)
    )
}

fn option_status_badges(app: &ShellApp, row: &PlanningTaskRow, spec: &OptionSpec) -> String {
    let mut badges = Vec::new();
    if app.option_locked_by_planning_preset(row.id, &spec.name) {
        badges.push("[LOCKED PRESET]");
    }
    if spec.advanced {
        badges.push("[ADVANCED]");
    }
    if badges.is_empty() {
        String::new()
    } else {
        format!(" {}", badges.join(" "))
    }
}

fn compact_selected_option_detail(
    app: &ShellApp,
    row: &PlanningTaskRow,
    spec: &OptionSpec,
    resolved: Option<&Value>,
) -> String {
    let value = option_display_value(spec, resolved);
    let source = option_provenance(app, row, spec, resolved);
    format!(
        "{} · {value} · {source} · {}",
        option_display_name(&spec.name),
        option_input_kind(spec)
    )
}

#[allow(clippy::too_many_arguments)]
fn append_selected_option_detail(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    row: &PlanningTaskRow,
    spec: &OptionSpec,
    index: usize,
    total: usize,
    resolved: Option<&Value>,
    width: usize,
    budget: usize,
    border_style: Style,
) {
    let body_width = width.saturating_sub(4).max(1);
    let detail = selected_option_detail_lines(app, row, spec, resolved, body_width);
    let title = option_detail_title(index, total, budget, detail.len());
    lines.push(pane_section_separator(&title, width, border_style));
    lines.extend(
        detail
            .into_iter()
            .take(budget)
            .map(|text| pane_body_line(&text, width, theme::primary(), border_style)),
    );
}

fn selected_option_detail_lines(
    app: &ShellApp,
    row: &PlanningTaskRow,
    spec: &OptionSpec,
    resolved: Option<&Value>,
    width: usize,
) -> Vec<String> {
    let mut lines = vec![option_name_label(app, row, spec), String::new()];
    let value = option_display_value(spec, resolved);
    push_wrapped_detail(&mut lines, &format!("Current: {value}"), width);
    let source = option_provenance(app, row, spec, resolved);
    push_wrapped_detail(&mut lines, &format!("From: {source}"), width);
    push_wrapped_detail(
        &mut lines,
        &format!("Input: {}", option_input_kind(spec)),
        width,
    );
    if !spec.choices.is_empty() {
        push_wrapped_detail(
            &mut lines,
            &format!("Choices: {}", spec.choices.join(", ")),
            width,
        );
    }
    push_wrapped_detail(&mut lines, &option_edit_hint(spec), width);
    lines.push(String::new());
    push_wrapped_detail(&mut lines, &spec.description, width);
    lines
}

fn push_wrapped_detail(lines: &mut Vec<String>, text: &str, width: usize) {
    lines.extend(wrap_text(text, width));
}

fn option_detail_title(index: usize, total: usize, budget: usize, detail: usize) -> String {
    if detail > budget {
        return format!(
            " OPTION {}/{} · DETAIL 1-{}/{} ",
            index + 1,
            total,
            budget,
            detail
        );
    }
    format!(" OPTION {}/{} ", index + 1, total)
}

fn option_display_value(spec: &OptionSpec, resolved: Option<&Value>) -> String {
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

fn pane_section_separator(title: &str, width: usize, border_style: Style) -> Line<'static> {
    border_line("├", title, "┤", width, border_style, theme::label())
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

fn finish_bordered_pane(
    mut lines: Vec<Line<'static>>,
    width: usize,
    height: usize,
    border_style: Style,
) -> Vec<Line<'static>> {
    if height <= 1 {
        lines.truncate(height);
        return lines;
    }
    let body_end = height - 1;
    lines.truncate(body_end);
    while lines.len() < body_end {
        lines.push(pane_body_line("", width, theme::muted(), border_style));
    }
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
            "Enter: runs nothing · reuse {} cached · Space runs",
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
    use crate::app::PlanningTaskId;
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

    fn planning_app(tasks: &[PlanningTaskId]) -> ShellApp {
        let target_dir = tempfile::tempdir().expect("temp target");
        let target = WorkspaceTarget::new(target_dir.path()).expect("workspace target");
        let mut app = ShellApp::new(V2Config::default(), Some(&target));
        app.engagement.set_phase(WorkflowPhase::Map);
        let rows = tasks
            .iter()
            .copied()
            .map(|task| PlanningTaskRow::for_task(task, target_dir.path()))
            .collect::<Vec<_>>();
        let selected = tasks.iter().copied().collect();
        app.engagement.planning_picker_mut().open(rows, selected);
        app
    }

    fn planning_text_lines(app: &ShellApp, width: u16, height: u16) -> Vec<String> {
        planning_picker_lines(app, Rect::new(0, 0, width, height))
            .iter()
            .map(line_text)
            .collect()
    }

    fn pane_column(lines: &[String], title: &str) -> usize {
        let line = lines
            .iter()
            .find(|line| line.contains(title))
            .unwrap_or_else(|| panic!("missing pane title {title:?}: {lines:#?}"));
        let byte = line.find(title).expect("title byte");
        display_width(&line[..byte])
    }

    fn assert_essential_planning_controls(rendered: &str) {
        for control in [
            "↑/↓ move",
            "Space outcome",
            "Tab pane",
            "←/→ phase",
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
        assert!(
            line_text(&wide).contains("runs fresh"),
            "wide keeps glosses"
        );
        let narrow = legend_line(30);
        let text = line_text(&narrow);
        assert!(text.contains("RUN"), "narrow keeps the words");
        assert!(!text.contains("runs fresh"), "narrow drops the glosses");
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
    fn imported_context_requires_its_document_and_never_claims_to_be_an_inline_action() {
        let task = PlanningTaskId::ImportThreatModel;
        let mut app = planning_app(&[task]);
        let row = app.engagement.planning_picker().tasks()[0].clone();
        assert!(unresolved_input_note(&app, &row)
            .unwrap()
            .contains("Choose a context JSON path"));
        app.engagement.set_option_override(
            task,
            "path".into(),
            serde_json::json!("owned-context.json"),
        );
        assert!(unresolved_input_note(&app, &row).is_none());
        assert!(!artifact_reason(&row).contains("inline"));
        assert!(!outcome_row_note(&app, &row, RowOutcome::Run).contains("no module runs"));
        let attached = planning_app(&[PlanningTaskId::AttachFiles]);
        let inline = attached.engagement.planning_picker().tasks()[0].clone();
        assert!(unresolved_input_note(&attached, &inline).is_none());
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
    fn mutation_survivor_option_pane_allocates_extra_list_row_at_sixteen_lines() {
        assert_eq!(option_pane_budgets(15).list, 3);
        assert_eq!(option_pane_budgets(16).list, 4);
    }

    #[test]
    fn wide_layout_is_stable_from_deterministic_to_prompt_backed_rows() {
        let area = Rect::new(0, 0, 120, 36);
        let mut app = planning_app(&[
            PlanningTaskId::GatherRepoContext,
            PlanningTaskId::BuildThreatModel,
        ]);

        assert_eq!(planning_layout_mode(area), PlanningLayoutMode::MasterDetail);
        app.engagement
            .planning_picker_mut()
            .set_cursor_to_task(PlanningTaskId::GatherRepoContext);
        let deterministic = planning_text_lines(&app, area.width, area.height);
        assert!(!app.planning_prompt_review_available());

        app.engagement
            .planning_picker_mut()
            .set_cursor_to_task(PlanningTaskId::BuildThreatModel);
        let model_backed = planning_text_lines(&app, area.width, area.height);
        assert!(app.planning_prompt_review_available());

        assert_eq!(deterministic.len(), model_backed.len());
        assert_eq!(
            pane_column(&deterministic, "OPTIONS · context:build"),
            pane_column(&model_backed, "OPTIONS · threat-model:build")
        );
        assert_eq!(
            deterministic
                .iter()
                .position(|line| line.contains("Enter run")),
            model_backed
                .iter()
                .position(|line| line.contains("Enter run"))
        );
        let hint_row = model_backed
            .iter()
            .position(|line| line.contains("Prompt review"))
            .unwrap_or_else(|| panic!("missing prompt review hint: {model_backed:#?}"));
        assert!(deterministic[hint_row].is_empty());
    }

    #[test]
    fn selected_option_renders_primitive_guidance_without_json() {
        let mut app = planning_app(&[PlanningTaskId::GatherRepoContext]);
        app.engagement
            .planning_picker_mut()
            .set_focus(PickerFocus::OptionsPane);
        app.move_planning_option_cursor(1);

        let lines = planning_text_lines(&app, 120, 36);
        let rendered = lines.join("\n");

        assert!(rendered.contains("Discovery"), "{rendered}");
        assert!(rendered.contains("Current: auto"), "{rendered}");
        assert!(rendered.contains("From: default"), "{rendered}");
        assert!(rendered.contains("Input: choice"), "{rendered}");
        assert!(
            rendered.contains("Choices: auto, flat, modules"),
            "{rendered}"
        );
        assert!(rendered.contains("Repository discovery"), "{rendered}");
        assert!(rendered.contains("mode."), "{rendered}");
        assert!(rendered.contains("Space cycles auto / flat / modules"));
        assert!(!rendered.contains("CANONICAL INPUT"), "{rendered}");
        assert!(!rendered.contains("{\""), "{rendered}");
    }

    #[test]
    fn option_rows_show_readable_advanced_and_locked_badges() {
        let mut advanced = planning_app(&[PlanningTaskId::GatherRepoContext]);
        advanced
            .engagement
            .planning_picker_mut()
            .set_focus(PickerFocus::OptionsPane);
        advanced.move_planning_option_cursor(2);
        let rendered = planning_text_lines(&advanced, 120, 36).join("\n");
        assert!(rendered.contains("Enrichment [ADVANCED]"), "{rendered}");

        let mut locked = planning_app(&[PlanningTaskId::BuildStrideThreatModel]);
        locked
            .engagement
            .planning_picker_mut()
            .set_focus(PickerFocus::OptionsPane);
        locked.move_planning_option_cursor(1);
        let rendered = planning_text_lines(&locked, 120, 36).join("\n");
        assert!(
            rendered.contains("Methodology [LOCKED PRESET]"),
            "{rendered}"
        );
    }

    #[test]
    fn option_window_tracks_the_cursor_on_option_rich_rows() {
        let mut app = planning_app(&[PlanningTaskId::BuildThreatModel]);
        app.engagement
            .planning_picker_mut()
            .set_focus(PickerFocus::OptionsPane);
        let option_count = app.planning_option_count_for_current_row();
        app.move_planning_option_cursor(option_count.saturating_sub(1) as isize);

        let rendered = planning_text_lines(&app, 120, 36).join("\n");

        assert!(rendered.contains(&format!("OPTION {option_count}/{option_count}")));
        assert!(rendered.contains("> Model [ADVANCED]"), "{rendered}");
        assert!(rendered.contains("Input: text"), "{rendered}");
        assert!(rendered.contains("Explicit provider:model"));
        assert!(rendered.contains("this tool run."), "{rendered}");
        assert!(!rendered.contains("> Target ="), "{rendered}");
        assert!(!rendered.contains("CANONICAL INPUT"), "{rendered}");
    }

    #[test]
    fn stacked_layout_gives_unused_task_space_to_options() {
        assert_eq!(stacked_pane_heights(8, 30), (11, 19));
        assert_eq!(stacked_pane_heights(1, 20), (4, 16));
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
    fn unresolved_input_names_the_first_reason_only() {
        assert_eq!(
            unresolved_input_message(
                "patch:finding",
                "patch:finding requires a fingerprint; open a finding first\ndetail"
            ),
            "needs input: requires a fingerprint"
        );
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
    fn failed_attempt_distinguishes_continue_from_retry_start() {
        let target = tempfile::tempdir().unwrap();
        let mut row =
            PlanningTaskRow::for_task(crate::app::PlanningTaskId::ScanAgenticSast, target.path());
        row.last_attempt = Some(crate::app::LastAttempt::Failed {
            resumable: true,
            resume_from: Some("evidence".to_string()),
        });
        assert_eq!(
            last_attempt_note(&row).as_deref(),
            Some("continue · resumes at evidence")
        );

        row.last_attempt = Some(crate::app::LastAttempt::Failed {
            resumable: false,
            resume_from: None,
        });
        assert_eq!(
            last_attempt_note(&row).as_deref(),
            Some("retry from start · failed last pass")
        );
    }

    #[test]
    fn partial_attempt_is_not_presented_as_a_failed_one() {
        let target = tempfile::tempdir().unwrap();
        let mut row =
            PlanningTaskRow::for_task(crate::app::PlanningTaskId::ScanAgenticSast, target.path());
        row.last_attempt = Some(crate::app::LastAttempt::Partial {
            resumable: false,
            resume_from: None,
        });
        assert_eq!(
            last_attempt_note(&row).as_deref(),
            Some("retry from start · partial last pass")
        );

        row.last_attempt = Some(crate::app::LastAttempt::Partial {
            resumable: true,
            resume_from: Some("evidence".to_string()),
        });
        assert_eq!(
            last_attempt_note(&row).as_deref(),
            Some("continue · partial · resumes at evidence")
        );

        row.last_attempt = Some(crate::app::LastAttempt::Partial {
            resumable: true,
            resume_from: None,
        });
        assert_eq!(
            last_attempt_note(&row).as_deref(),
            Some("continue from checkpoint · partial")
        );
    }

    #[test]
    fn a_cache_a_partial_pass_left_behind_is_not_offered_as_a_complete_one() {
        let target = tempfile::tempdir().unwrap();
        let mut row =
            PlanningTaskRow::for_task(crate::app::PlanningTaskId::BuildThreatModel, target.path());
        row.artifact_state = PlanningArtifactState::Cached;
        row.last_attempt = Some(crate::app::LastAttempt::Partial {
            resumable: false,
            resume_from: None,
        });

        // Reuse is the one outcome where the cached note wins over
        // `last_attempt_note`, so it has to carry the disclosure itself.
        assert_eq!(
            cached_row_note(&row, RowOutcome::Reuse).as_deref(),
            Some("cached (partial) · Space runs fresh")
        );

        // A deselected cached row is Skip, where the cached note declines and
        // the partial wording reaches the operator through `last_attempt_note`.
        assert_eq!(cached_row_note(&row, RowOutcome::Skip), None);
        assert_eq!(
            last_attempt_note(&row).as_deref(),
            Some("retry from start · partial last pass")
        );

        // A completed pass still reads as a plain cache.
        row.last_attempt = Some(crate::app::LastAttempt::Completed);
        assert_eq!(
            cached_row_note(&row, RowOutcome::Reuse).as_deref(),
            Some("cached · Space runs fresh")
        );
    }

    #[test]
    fn wide_planning_keeps_essential_controls_at_120x40() {
        assert_essential_planning_controls(&rendered_planning_lines(120, 40));
    }

    #[test]
    fn wide_planning_keeps_essential_controls_at_120x36() {
        assert_essential_planning_controls(&rendered_planning_lines(120, 36));
    }

    #[test]
    fn wide_planning_keeps_essential_controls_at_100x30() {
        assert_essential_planning_controls(&rendered_planning_lines(100, 30));
    }
}
