use crate::ActivitySession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFooterModel {
    pub(crate) body: String,
    pub(crate) hints: &'static [ActivityFooterHint],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActivityFooterHint {
    pub(crate) key: &'static str,
    pub(crate) hint: &'static str,
}

const FULL_HINTS: &[ActivityFooterHint] = &[
    ActivityFooterHint {
        key: "j/k",
        hint: "scroll",
    },
    ActivityFooterHint {
        key: "Tab",
        hint: "pane",
    },
    ActivityFooterHint {
        key: "V",
        hint: "verbose",
    },
    ActivityFooterHint {
        key: "p",
        hint: "pause",
    },
    ActivityFooterHint {
        key: "R",
        hint: "reset",
    },
    ActivityFooterHint {
        key: "Enter",
        hint: "focus",
    },
    ActivityFooterHint {
        key: "c",
        hint: "cancel",
    },
];

const NARROW_HINTS: &[ActivityFooterHint] = &[
    ActivityFooterHint {
        key: "j/k",
        hint: "scroll",
    },
    ActivityFooterHint {
        key: "Tab",
        hint: "pane",
    },
    ActivityFooterHint {
        key: "V",
        hint: "verbose",
    },
    ActivityFooterHint {
        key: "p",
        hint: "pause",
    },
    ActivityFooterHint {
        key: "R",
        hint: "reset",
    },
    ActivityFooterHint {
        key: "c",
        hint: "cancel",
    },
];

pub(crate) fn activity_footer_model(session: &ActivitySession, width: u16) -> ActivityFooterModel {
    ActivityFooterModel {
        body: focus_body(session),
        hints: footer_hints(width),
    }
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
        assert_eq!(model.hints.last().map(|hint| hint.key), Some("c"));
    }

    #[test]
    fn activity_footer_model_handles_empty_and_missing_focus() {
        let mut session = ActivitySession::new("r-1");
        assert_eq!(
            activity_footer_model(&session, 80).body,
            " ▸ FOCUS  hover [j/k] to inspect a task"
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
                .map(|hint| hint.key)
                .collect::<Vec<_>>(),
            vec!["j/k", "Tab", "V", "p", "R", "c"]
        );
    }
}
