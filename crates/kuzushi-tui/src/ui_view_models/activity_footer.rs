use crate::ActivitySession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFooterModel {
    pub(crate) body: String,
    pub(crate) body_line: String,
    pub(crate) hints: &'static [ActivityFooterHint],
    pub(crate) plain_hints: Vec<(&'static str, &'static str)>,
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
    footer_hint!("j/k", "scroll"),
    footer_hint!("Tab", "pane"),
    footer_hint!("V", "verbose"),
    footer_hint!("p", "pause"),
    footer_hint!("R", "reset"),
    footer_hint!("Enter", "focus"),
    footer_hint!("c", "cancel"),
];

const NARROW_HINTS: &[ActivityFooterHint] = &[
    footer_hint!("j/k", "scroll"),
    footer_hint!("Tab", "pane"),
    footer_hint!("V", "verbose"),
    footer_hint!("p", "pause"),
    footer_hint!("R", "reset"),
    footer_hint!("c", "cancel"),
];

pub(crate) fn activity_footer_model(session: &ActivitySession, width: u16) -> ActivityFooterModel {
    let hints = footer_hints(width);
    let body = focus_body(session);
    ActivityFooterModel {
        body_line: fit(&body, width as usize),
        body,
        hints,
        plain_hints: plain_hint_pairs(hints),
    }
}

fn plain_hint_pairs(hints: &[ActivityFooterHint]) -> Vec<(&'static str, &'static str)> {
    hints
        .iter()
        .map(|hint| (hint.plain_key_text, hint.plain_hint_text))
        .collect()
}

fn focus_body(session: &ActivitySession) -> String {
    match session.focus_task.as_ref() {
        Some(task_id) => focused_task_body(session, task_id),
        None => " ▸ FOCUS  hover [j/k] to inspect a task".to_string(),
    }
}

fn focused_task_body(session: &ActivitySession, task_id: &str) -> String {
    session
        .tasks
        .get(task_id)
        .map(focused_task_row_body)
        .unwrap_or_else(|| format!(" ▸ FOCUS  {task_id}  (not yet recorded)"))
}

fn focused_task_row_body(row: &crate::DagTaskRow) -> String {
    format!(
        " ▸ FOCUS  {task}  {state:?}  steps {n}  {label}",
        task = row.task_id,
        state = row.state,
        n = row.steps_done,
        label = row.last_label,
    )
}

fn footer_hints(width: u16) -> &'static [ActivityFooterHint] {
    if width < 100 {
        return NARROW_HINTS;
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
    use crate::{DagTaskRow, DagTaskState};

    #[test]
    fn activity_footer_model_projects_focused_task() {
        let mut session = ActivitySession::new("r-1");
        let mut row = DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new());
        row.state = DagTaskState::Active;
        row.steps_done = 3;
        row.last_label = "reviewing evidence".to_string();
        session.focus_task = Some(row.task_id.clone());
        session.tasks.insert(row.task_id.clone(), row);

        let model = activity_footer_model(&session, 120);

        assert_eq!(
            model.body,
            " ▸ FOCUS  triage:run  Active  steps 3  reviewing evidence"
        );
        assert_eq!(model.body_line, model.body);
        assert_eq!(
            model.hints.last().map(|hint| hint.plain_key_text),
            Some("c")
        );
        assert_eq!(
            model.hints.first().map(|hint| hint.full_key_text),
            Some("[j/k")
        );
        assert_eq!(
            model.hints.first().map(|hint| hint.full_hint_text),
            Some("scroll]")
        );
    }

    #[test]
    fn activity_footer_model_handles_empty_and_missing_focus() {
        let mut session = ActivitySession::new("r-1");
        assert_eq!(
            activity_footer_model(&session, 80).body,
            " ▸ FOCUS  hover [j/k] to inspect a task"
        );
        assert_eq!(
            activity_footer_model(&session, 18).body_line,
            " ▸ FOCUS  hover […"
        );

        session.focus_task = Some("patch:finding".to_string());
        assert_eq!(
            activity_footer_model(&session, 80).body,
            " ▸ FOCUS  patch:finding  (not yet recorded)"
        );
        assert_eq!(
            activity_footer_model(&session, 80)
                .hints
                .iter()
                .map(|hint| hint.plain_key_text)
                .collect::<Vec<_>>(),
            vec!["j/k", "Tab", "V", "p", "R", "c"]
        );
        assert_eq!(
            activity_footer_model(&session, 80).plain_hints,
            vec![
                ("j/k", "scroll"),
                ("Tab", "pane"),
                ("V", "verbose"),
                ("p", "pause"),
                ("R", "reset"),
                ("c", "cancel"),
            ]
        );
    }
}
