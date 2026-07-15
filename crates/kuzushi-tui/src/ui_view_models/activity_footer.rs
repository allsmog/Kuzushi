use crate::{ActivityRouteState, ActivitySession, InputMode, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFooterModel {
    pub(crate) body: String,
    pub(crate) body_line: String,
    pub(crate) hints: Vec<ActivityFooterHint>,
    /// Hints wrapped to the pane width — one row per inner Vec, so narrow
    /// terminals get a second hint line instead of keys clipped to "[c".
    pub(crate) hint_rows: Vec<Vec<ActivityFooterHint>>,
    pub(crate) steer_line: Option<String>,
    pub(crate) steer_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFooterHint {
    pub(crate) full_key_text: String,
    pub(crate) full_hint_text: String,
    pub(crate) plain_key_text: String,
    pub(crate) plain_hint_text: &'static str,
    action_id: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
struct ActivityFooterHintSpec {
    default_key: &'static str,
    hint: &'static str,
    action_id: Option<&'static str>,
}

const NAV_FULL_HINTS: &[ActivityFooterHintSpec] = &[
    hint_spec("j/k/g/G", "scroll", None),
    hint_spec("Tab", "pane", Some("cycle_pane")),
    hint_spec("V", "verbose", Some("verbose")),
    hint_spec("Space", "pause", Some("pause_feed")),
    hint_spec("x", "reset view", None),
    hint_spec("Enter", "focus", Some("focus")),
    hint_spec("b", "background", Some("background")),
    hint_spec("s", "steer", Some("steer")),
];

/// Taskless (single-tool) runs collapse the TASKS pane, which pins focus to
/// OUTPUT: `Tab` (pane toggle) and `Enter` (focus a task) have no task target,
/// so the footer must not advertise them.
const NAV_TASKLESS_HINTS: &[ActivityFooterHintSpec] = &[
    hint_spec("j/k/g/G", "scroll", None),
    hint_spec("V", "verbose", Some("verbose")),
    hint_spec("Space", "pause", Some("pause_feed")),
    hint_spec("x", "reset view", None),
    hint_spec("b", "background", Some("background")),
    hint_spec("s", "steer", Some("steer")),
];

const fn hint_spec(
    default_key: &'static str,
    hint: &'static str,
    action_id: Option<&'static str>,
) -> ActivityFooterHintSpec {
    ActivityFooterHintSpec {
        default_key,
        hint,
        action_id,
    }
}

pub(crate) fn activity_footer_model(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: u16,
    running_tool: Option<&str>,
    abort_pending: bool,
    _input_mode: InputMode,
) -> ActivityFooterModel {
    let hints = footer_hints(session);
    let body = focus_body(session, route, running_tool, abort_pending);
    let steer_line = route
        .steer_editor
        .as_ref()
        .map(|editor| format!(" STEER > {}", editor.input));
    let steer_error = route
        .steer_editor
        .as_ref()
        .and_then(|editor| editor.error.clone());
    ActivityFooterModel {
        body_line: fit(&body, width as usize),
        body,
        hint_rows: wrap_hints(&hints, width as usize),
        hints,
        steer_line,
        steer_error,
    }
}

pub(crate) fn resolve_activity_footer_bindings(
    mut model: ActivityFooterModel,
    app: &ShellApp,
    width: u16,
) -> ActivityFooterModel {
    model.hints = model
        .hints
        .into_iter()
        .filter_map(|hint| resolve_hint_binding(hint, app))
        .collect();
    model.hint_rows = wrap_hints(&model.hints, width as usize);
    model
}

fn resolve_hint_binding(hint: ActivityFooterHint, app: &ShellApp) -> Option<ActivityFooterHint> {
    let Some(action_id) = hint.action_id else {
        return Some(hint);
    };
    let defaults = [hint.plain_key_text.as_str()];
    let bindings = app
        .ui()
        .keymap_binding_labels("run_focus", action_id, &defaults);
    (!bindings.is_empty())
        .then(|| ActivityFooterHint::new(bindings.join("/"), hint.plain_hint_text, hint.action_id))
}

impl ActivityFooterHint {
    fn new(key: impl Into<String>, hint: &'static str, action_id: Option<&'static str>) -> Self {
        let plain_key_text = key.into();
        Self {
            full_key_text: format!("[{plain_key_text}"),
            full_hint_text: format!("{hint}]"),
            plain_key_text,
            plain_hint_text: hint,
            action_id,
        }
    }
}

/// Greedy-wrap hints into rows that fit `width`; every key stays visible.
fn wrap_hints(hints: &[ActivityFooterHint], width: usize) -> Vec<Vec<ActivityFooterHint>> {
    let mut rows: Vec<Vec<ActivityFooterHint>> = Vec::new();
    let mut row: Vec<ActivityFooterHint> = Vec::new();
    let mut used = 1usize; // leading space
    for hint in hints {
        let cell = hint_display_width(hint);
        if !row.is_empty() && used + cell > width {
            rows.push(std::mem::take(&mut row));
            used = 1;
        }
        used += cell;
        row.push(hint.clone());
    }
    if !row.is_empty() {
        rows.push(row);
    }
    rows
}

fn hint_display_width(hint: &ActivityFooterHint) -> usize {
    // Rendered as `[key hint] ` — bracketed pair plus one separator space.
    hint.full_key_text.chars().count() + 1 + hint.full_hint_text.chars().count() + 1
}

fn focus_body(
    session: &ActivitySession,
    route: &ActivityRouteState,
    running_tool: Option<&str>,
    abort_pending: bool,
) -> String {
    if abort_pending {
        return " ⚠ ABORT REQUESTED  waiting for cleanup · Ctrl+C stays here".to_string();
    }
    // Taskless (single-tool) runs have nothing to focus — "select a task to
    // inspect a task" would point at a pane that isn't on screen.
    if session.tasks.is_empty() {
        return taskless_body(running_tool);
    }
    tasked_body(session, route)
}

fn tasked_body(session: &ActivitySession, route: &ActivityRouteState) -> String {
    if route.effective_pane_focus(session) == crate::PaneFocus::Right {
        return " ● OUTPUT  live trace · j/k scroll · switch pane for steps · Ctrl+C aborts"
            .to_string();
    }
    match route.focus_task.as_ref() {
        Some(task_id) => focused_task_body(session, task_id),
        None => " ● FOCUS  [j/k] select a task to inspect".to_string(),
    }
}

fn taskless_body(running_tool: Option<&str>) -> String {
    match running_tool {
        Some(tool) => format!(" ● RUNNING  {tool} — output streams above · Ctrl+C aborts"),
        None => " ● FOCUS  no task rows this run".to_string(),
    }
}

fn focused_task_body(session: &ActivitySession, task_id: &str) -> String {
    session
        .tasks
        .get(task_id)
        .map(focused_task_row_body)
        .unwrap_or_else(|| format!(" ● FOCUS  {task_id}  (not yet recorded)"))
}

fn focused_task_row_body(row: &crate::DagTaskRow) -> String {
    format!(
        " ● FOCUS  {task}  {state:?}  steps {n}  {label}",
        task = row.task_id,
        state = row.state,
        n = row.steps_done,
        label = row.last_label,
    )
}

/// Hint selection follows what the keys can actually do (narrow widths are
/// handled by `wrap_hints`, which keeps every key visible): with no DAG tasks
/// the pane-focus keys are inert and disappear from the hints.
fn footer_hints(session: &ActivitySession) -> Vec<ActivityFooterHint> {
    let specs = if session.tasks.is_empty() {
        NAV_TASKLESS_HINTS
    } else {
        NAV_FULL_HINTS
    };
    specs
        .iter()
        .map(|spec| ActivityFooterHint::new(spec.default_key, spec.hint, spec.action_id))
        .collect()
}

fn fit(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len <= width {
        return value.to_string();
    }
    if width <= 1 {
        return "…".repeat(width);
    }
    let keep = width.saturating_sub(1);
    format!("{}…", value.chars().take(keep).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DagTaskRow, DagTaskState, PaneFocus};

    #[test]
    fn activity_footer_model_projects_focused_task() {
        let mut session = ActivitySession::new("r-1");
        let mut route = ActivityRouteState::default();
        let mut row = DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new());
        row.state = DagTaskState::Active;
        row.steps_done = 3;
        row.last_label = "reviewing evidence".to_string();
        route.focus_task = Some(row.task_id.clone());
        session.tasks.insert(row.task_id.clone(), row);

        let model = activity_footer_model(&session, &route, 120, None, false, InputMode::Navigate);

        assert_eq!(
            model.body,
            " ● FOCUS  triage:run  Active  steps 3  reviewing evidence"
        );
        assert_eq!(model.body_line, model.body);
        assert_eq!(
            model.hints.last().map(|hint| hint.plain_key_text.as_str()),
            Some("s")
        );
        assert_eq!(
            model.hints.first().map(|hint| hint.full_key_text.as_str()),
            Some("[j/k/g/G")
        );
        assert_eq!(
            model.hints.first().map(|hint| hint.full_hint_text.as_str()),
            Some("scroll]")
        );
    }

    #[test]
    fn hints_wrap_to_extra_rows_on_narrow_terminals_without_losing_keys() {
        let session = ActivitySession::new("r-1");
        let route = ActivityRouteState::default();
        let wide = activity_footer_model(&session, &route, 160, None, false, InputMode::Navigate);
        assert_eq!(wide.hint_rows.len(), 1, "wide terminals keep one row");

        let narrow = activity_footer_model(&session, &route, 40, None, false, InputMode::Navigate);
        assert!(narrow.hint_rows.len() > 1, "narrow terminals wrap");
        let total: usize = narrow.hint_rows.iter().map(Vec::len).sum();
        assert_eq!(total, narrow.hints.len(), "every key survives the wrap");
    }

    #[test]
    fn taskless_runs_do_not_advertise_the_inert_pane_focus_keys() {
        // With no DAG tasks the TASKS pane is collapsed and focus is pinned to
        // OUTPUT — Tab and Enter are task controls, so they must not appear.
        let taskless = ActivitySession::new("r-1");
        let route = ActivityRouteState::default();
        let taskless_model =
            activity_footer_model(&taskless, &route, 120, None, false, InputMode::Navigate);
        let keys = plain_keys(&taskless_model);
        assert!(!keys.contains(&"Tab"), "{keys:?}");
        assert!(!keys.contains(&"Enter"), "{keys:?}");

        let mut with_tasks = ActivitySession::new("r-2");
        with_tasks.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new()),
        );
        let with_tasks_model =
            activity_footer_model(&with_tasks, &route, 120, None, false, InputMode::Navigate);
        let keys = plain_keys(&with_tasks_model);
        assert!(keys.contains(&"Tab"), "{keys:?}");
        assert!(keys.contains(&"Enter"), "{keys:?}");
    }

    #[test]
    fn taskless_footer_names_the_running_tool_or_states_the_absence() {
        // Never tell the operator to inspect tasks that don't exist.
        let session = ActivitySession::new("r-1");
        let route = ActivityRouteState::default();
        assert_eq!(
            activity_footer_model(
                &session,
                &route,
                80,
                Some("threat-model:build"),
                false,
                InputMode::Navigate,
            )
            .body,
            " ● RUNNING  threat-model:build — output streams above · Ctrl+C aborts"
        );
        assert_eq!(
            activity_footer_model(&session, &route, 80, None, false, InputMode::Navigate).body,
            " ● FOCUS  no task rows this run"
        );
    }

    #[test]
    fn abort_pending_footer_overrides_focus_body() {
        let mut session = ActivitySession::new("r-1");
        let route = ActivityRouteState::default();
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new()),
        );

        let model = activity_footer_model(
            &session,
            &route,
            80,
            Some("triage:run"),
            true,
            InputMode::Navigate,
        );

        assert!(model.body.contains("ABORT REQUESTED"));
        assert!(model.body.contains("Ctrl+C stays here"));
    }

    #[test]
    fn output_footer_names_the_live_output_window() {
        let mut session = ActivitySession::new("r-1");
        let mut route = ActivityRouteState::default();
        session.tasks.insert(
            "threat-model:build".to_string(),
            DagTaskRow::queued(
                "threat-model:build".into(),
                "threat-model".into(),
                Vec::new(),
            ),
        );
        route.pane_focus = PaneFocus::Right;

        assert_eq!(
            activity_footer_model(&session, &route, 100, None, false, InputMode::Navigate).body,
            " ● OUTPUT  live trace · j/k scroll · switch pane for steps · Ctrl+C aborts"
        );
    }

    #[test]
    fn context_build_footer_uses_the_same_output_contract() {
        let mut session = ActivitySession::new("context-run");
        let mut route = ActivityRouteState::default();
        session.tasks.insert(
            "context:build".to_string(),
            DagTaskRow::queued("context:build".into(), "context".into(), Vec::new()),
        );
        route.pane_focus = PaneFocus::Right;

        let model = activity_footer_model(
            &session,
            &route,
            120,
            Some("context:build"),
            false,
            InputMode::Navigate,
        );

        assert!(model.body.contains("OUTPUT"), "{}", model.body);
        let keys = plain_keys(&model);
        assert!(!keys.contains(&"[/]"), "{keys:?}");
        assert!(!keys.contains(&"f"), "{keys:?}");
        assert!(!keys.contains(&"o"), "{keys:?}");
    }

    #[test]
    fn activity_footer_model_handles_empty_and_missing_focus() {
        let mut session = ActivitySession::new("r-1");
        let mut route = ActivityRouteState::default();
        // With tasks present, the hover hint and focus drill return.
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new()),
        );
        assert_eq!(
            activity_footer_model(&session, &route, 80, None, false, InputMode::Navigate).body,
            " ● FOCUS  [j/k] select a task to inspect"
        );
        assert_eq!(
            activity_footer_model(&session, &route, 18, None, false, InputMode::Navigate).body_line,
            " ● FOCUS  [j/k] s…"
        );

        route.focus_task = Some("patch:finding".to_string());
        assert_eq!(
            activity_footer_model(&session, &route, 80, None, false, InputMode::Navigate).body,
            " ● FOCUS  patch:finding  (not yet recorded)"
        );
        assert_eq!(
            plain_keys(&activity_footer_model(
                &session,
                &route,
                80,
                None,
                false,
                InputMode::Navigate,
            )),
            vec!["j/k/g/G", "Tab", "V", "Space", "x", "Enter", "b", "s"]
        );
    }

    #[test]
    fn activity_footer_model_exposes_run_focus_hint_pairs() {
        let mut session = ActivitySession::new("r-1");
        let route = ActivityRouteState::default();
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new()),
        );

        assert_eq!(
            plain_pairs(&activity_footer_model(
                &session,
                &route,
                80,
                None,
                false,
                InputMode::Navigate,
            )),
            vec![
                ("j/k/g/G", "scroll"),
                ("Tab", "pane"),
                ("V", "verbose"),
                ("Space", "pause"),
                ("x", "reset view"),
                ("Enter", "focus"),
                ("b", "background"),
                ("s", "steer"),
            ]
        );
    }

    #[test]
    fn input_mode_does_not_change_the_run_owned_footer_contract() {
        let mut session = ActivitySession::new("r-1");
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new()),
        );
        let route = ActivityRouteState::default();

        let model = activity_footer_model(&session, &route, 120, None, false, InputMode::Prompt);
        let pairs = plain_pairs(&model);

        assert!(pairs.contains(&("s", "steer")));
        assert!(!pairs.iter().any(|(key, _)| *key == "F2"));

        let running = activity_footer_model(
            &session,
            &route,
            120,
            Some("threat-model:build"),
            false,
            InputMode::Prompt,
        );
        assert!(running.body.contains("● FOCUS"));
        assert!(!running.body.contains("threat-model:build"));
    }

    #[test]
    fn steer_editor_projects_input_and_inline_validation_error() {
        let session = ActivitySession::new("r-1");
        let mut route = ActivityRouteState::default();
        route.open_steer_editor();
        let editor = route.steer_editor.as_mut().expect("steer editor");
        editor.input = "findings".to_string();
        editor.error = Some("steer accepts only: run <tool> [input]".to_string());

        let model = activity_footer_model(&session, &route, 120, None, false, InputMode::Navigate);

        assert_eq!(model.steer_line.as_deref(), Some(" STEER > findings"));
        assert!(model
            .steer_error
            .as_deref()
            .is_some_and(|error| error.contains("run <tool>")));
    }

    fn plain_keys(model: &ActivityFooterModel) -> Vec<&str> {
        plain_pairs(model).into_iter().map(|(key, _)| key).collect()
    }

    fn plain_pairs(model: &ActivityFooterModel) -> Vec<(&str, &str)> {
        model
            .hint_rows
            .iter()
            .flatten()
            .map(|hint| (hint.plain_key_text.as_str(), hint.plain_hint_text))
            .collect()
    }
}
