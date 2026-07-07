use crate::ActivitySession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFooterModel {
    pub(crate) body: String,
    pub(crate) body_line: String,
    pub(crate) hints: &'static [ActivityFooterHint],
    /// Hints wrapped to the pane width — one row per inner Vec, so narrow
    /// terminals get a second hint line instead of keys clipped to "[c".
    pub(crate) hint_rows: Vec<Vec<ActivityFooterHint>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivityFooterHint {
    pub(crate) full_key_text: &'static str,
    pub(crate) full_hint_text: &'static str,
    pub(crate) plain_key_text: &'static str,
    pub(crate) plain_hint_text: &'static str,
}

macro_rules! footer_hint {
    ($key:literal, $hint:literal) => {
        ActivityFooterHint {
            full_key_text: concat!("[", $key),
            full_hint_text: concat!($hint, "]"),
            plain_key_text: $key,
            plain_hint_text: $hint,
        }
    };
}

const FULL_HINTS: &[ActivityFooterHint] = &[
    footer_hint!("j/k/g/G", "scroll"),
    footer_hint!("Tab", "pane"),
    footer_hint!("[/]", "views"),
    footer_hint!("f", "findings"),
    footer_hint!("o", "open"),
    footer_hint!("V", "verbose"),
    footer_hint!("Space", "pause"),
    footer_hint!("x", "reset view"),
    footer_hint!("Enter", "focus"),
    footer_hint!("Esc", "leave"),
];

/// Taskless (single-tool) runs collapse the TASKS pane, which pins focus to
/// OUTPUT: `Tab` (pane toggle) and `Enter` (focus a task) have no task target,
/// so the footer must not advertise them.
const TASKLESS_HINTS: &[ActivityFooterHint] = &[
    footer_hint!("j/k/g/G", "scroll"),
    footer_hint!("[/]", "views"),
    footer_hint!("f", "findings"),
    footer_hint!("o", "open"),
    footer_hint!("V", "verbose"),
    footer_hint!("Space", "pause"),
    footer_hint!("x", "reset view"),
    footer_hint!("Esc", "leave"),
];

pub(crate) fn activity_footer_model(
    session: &ActivitySession,
    width: u16,
    running_tool: Option<&str>,
    abort_pending: bool,
) -> ActivityFooterModel {
    let hints = footer_hints(session);
    let body = focus_body(session, running_tool, abort_pending);
    ActivityFooterModel {
        body_line: fit(&body, width as usize),
        body,
        hints,
        hint_rows: wrap_hints(hints, width as usize),
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
        row.push(*hint);
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
    running_tool: Option<&str>,
    abort_pending: bool,
) -> String {
    if abort_pending {
        return " ⚠ ABORT REQUESTED  waiting for cleanup · Ctrl+C stays here".to_string();
    }
    // Taskless (single-tool) runs have nothing to focus — "hover to
    // inspect a task" would point at a pane that isn't on screen.
    if session.tasks.is_empty() {
        return taskless_body(running_tool);
    }
    tasked_body(session)
}

fn tasked_body(session: &ActivitySession) -> String {
    if session.effective_pane_focus() == crate::PaneFocus::Right {
        return format!(
            " ● OUTPUT  {} · j/k item · f findings · o open",
            session.deck_page.label()
        );
    }
    match session.focus_task.as_ref() {
        Some(task_id) => focused_task_body(session, task_id),
        None => " ● FOCUS  hover [j/k] to inspect a task".to_string(),
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
fn footer_hints(session: &ActivitySession) -> &'static [ActivityFooterHint] {
    if session.tasks.is_empty() {
        return TASKLESS_HINTS;
    }
    FULL_HINTS
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
        let mut row = DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new());
        row.state = DagTaskState::Active;
        row.steps_done = 3;
        row.last_label = "reviewing evidence".to_string();
        session.focus_task = Some(row.task_id.clone());
        session.tasks.insert(row.task_id.clone(), row);

        let model = activity_footer_model(&session, 120, None, false);

        assert_eq!(
            model.body,
            " ● FOCUS  triage:run  Active  steps 3  reviewing evidence"
        );
        assert_eq!(model.body_line, model.body);
        assert_eq!(
            model.hints.last().map(|hint| hint.plain_key_text),
            Some("Esc")
        );
        assert_eq!(
            model.hints.first().map(|hint| hint.full_key_text),
            Some("[j/k/g/G")
        );
        assert_eq!(
            model.hints.first().map(|hint| hint.full_hint_text),
            Some("scroll]")
        );
    }

    #[test]
    fn hints_wrap_to_extra_rows_on_narrow_terminals_without_losing_keys() {
        let session = ActivitySession::new("r-1");
        let wide = activity_footer_model(&session, 160, None, false);
        assert_eq!(wide.hint_rows.len(), 1, "wide terminals keep one row");

        let narrow = activity_footer_model(&session, 40, None, false);
        assert!(narrow.hint_rows.len() > 1, "narrow terminals wrap");
        let total: usize = narrow.hint_rows.iter().map(Vec::len).sum();
        assert_eq!(total, narrow.hints.len(), "every key survives the wrap");
    }

    #[test]
    fn taskless_runs_do_not_advertise_the_inert_pane_focus_keys() {
        // With no DAG tasks the TASKS pane is collapsed and focus is pinned to
        // OUTPUT — Tab and Enter are task controls, so they must not appear.
        let taskless = ActivitySession::new("r-1");
        let keys = plain_keys(&activity_footer_model(&taskless, 120, None, false));
        assert!(!keys.contains(&"Tab"), "{keys:?}");
        assert!(!keys.contains(&"Enter"), "{keys:?}");

        let mut with_tasks = ActivitySession::new("r-2");
        with_tasks.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new()),
        );
        let keys = plain_keys(&activity_footer_model(&with_tasks, 120, None, false));
        assert!(keys.contains(&"Tab"), "{keys:?}");
        assert!(keys.contains(&"Enter"), "{keys:?}");
    }

    #[test]
    fn taskless_footer_names_the_running_tool_or_states_the_absence() {
        // Never tell the operator to inspect tasks that don't exist.
        let session = ActivitySession::new("r-1");
        assert_eq!(
            activity_footer_model(&session, 80, Some("threat-model:build"), false).body,
            " ● RUNNING  threat-model:build — output streams above · Ctrl+C aborts"
        );
        assert_eq!(
            activity_footer_model(&session, 80, None, false).body,
            " ● FOCUS  no task rows this run"
        );
    }

    #[test]
    fn abort_pending_footer_overrides_focus_body() {
        let mut session = ActivitySession::new("r-1");
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new()),
        );

        let model = activity_footer_model(&session, 80, Some("triage:run"), true);

        assert!(model.body.contains("ABORT REQUESTED"));
        assert!(model.body.contains("Ctrl+C stays here"));
    }

    #[test]
    fn artifact_deck_footer_names_right_pane_navigation() {
        let mut session = ActivitySession::new("r-1");
        session.tasks.insert(
            "threat-model:build".to_string(),
            DagTaskRow::queued(
                "threat-model:build".into(),
                "threat-model".into(),
                Vec::new(),
            ),
        );
        session.set_deck_page(crate::ActivityDeckPage::Dfd);
        session.pane_focus = PaneFocus::Right;

        assert_eq!(
            activity_footer_model(&session, 100, None, false).body,
            " ● OUTPUT  dfd · j/k item · f findings · o open"
        );
    }

    #[test]
    fn activity_footer_model_handles_empty_and_missing_focus() {
        let mut session = ActivitySession::new("r-1");
        // With tasks present, the hover hint and focus drill return.
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new()),
        );
        assert_eq!(
            activity_footer_model(&session, 80, None, false).body,
            " ● FOCUS  hover [j/k] to inspect a task"
        );
        assert_eq!(
            activity_footer_model(&session, 18, None, false).body_line,
            " ● FOCUS  hover […"
        );

        session.focus_task = Some("patch:finding".to_string());
        assert_eq!(
            activity_footer_model(&session, 80, None, false).body,
            " ● FOCUS  patch:finding  (not yet recorded)"
        );
        assert_eq!(
            plain_keys(&activity_footer_model(&session, 80, None, false)),
            vec!["j/k/g/G", "Tab", "[/]", "f", "o", "V", "Space", "x", "Enter", "Esc"]
        );
    }

    #[test]
    fn activity_footer_model_exposes_deck_hint_pairs() {
        let mut session = ActivitySession::new("r-1");
        session.tasks.insert(
            "triage:run".to_string(),
            DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new()),
        );

        assert_eq!(
            plain_pairs(&activity_footer_model(&session, 80, None, false)),
            vec![
                ("j/k/g/G", "scroll"),
                ("Tab", "pane"),
                ("[/]", "views"),
                ("f", "findings"),
                ("o", "open"),
                ("V", "verbose"),
                ("Space", "pause"),
                ("x", "reset view"),
                ("Enter", "focus"),
                ("Esc", "leave"),
            ]
        );
    }

    fn plain_keys(model: &ActivityFooterModel) -> Vec<&'static str> {
        plain_pairs(model).into_iter().map(|(key, _)| key).collect()
    }

    fn plain_pairs(model: &ActivityFooterModel) -> Vec<(&'static str, &'static str)> {
        model
            .hint_rows
            .iter()
            .flatten()
            .map(|hint| (hint.plain_key_text, hint.plain_hint_text))
            .collect()
    }
}
