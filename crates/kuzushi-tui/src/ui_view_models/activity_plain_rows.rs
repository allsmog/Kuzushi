use super::activity_dag_rows::{activity_dag_pane_rows, ActivityDagPaneRow, ActivityDagRowTone};
use super::activity_feed_rows::{ActivityFeedPaneRow, ActivityFeedRowTone};
use crate::ActivitySession;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPlainPaneRow {
    pub(crate) dag: ActivityPlainDagCell,
    pub(crate) separator: &'static str,
    pub(crate) feed: ActivityPlainFeedCell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPlainDagCell {
    pub(crate) text: String,
    pub(crate) tone: Option<ActivityDagRowTone>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPlainFeedCell {
    pub(crate) text: String,
    pub(crate) tone: Option<ActivityFeedRowTone>,
}

pub(crate) fn activity_plain_pane_rows(
    session: &ActivitySession,
    dag_width: usize,
    feed_width: usize,
    now: Instant,
    output_rows: &[ActivityFeedPaneRow],
    running_tool: Option<&str>,
) -> Vec<ActivityPlainPaneRow> {
    let dag_rows = activity_dag_pane_rows(session, dag_width, now, running_tool);
    let row_count = dag_rows.len().max(output_rows.len());
    (0..row_count)
        .map(|index| ActivityPlainPaneRow {
            dag: dag_cell(dag_rows.get(index), dag_width),
            separator: " │ ",
            feed: feed_cell(output_rows.get(index), feed_width),
        })
        .collect()
}

fn dag_cell(row: Option<&ActivityDagPaneRow>, width: usize) -> ActivityPlainDagCell {
    match row {
        Some(row) => ActivityPlainDagCell {
            text: fit_or_pad(&row.text, width),
            tone: Some(row.tone),
        },
        None => ActivityPlainDagCell {
            text: " ".repeat(width),
            tone: None,
        },
    }
}

fn feed_cell(row: Option<&ActivityFeedPaneRow>, width: usize) -> ActivityPlainFeedCell {
    match row {
        Some(row) => ActivityPlainFeedCell {
            text: fit_or_pad(&row.text, width),
            tone: Some(row.tone),
        },
        None => ActivityPlainFeedCell {
            text: " ".repeat(width),
            tone: None,
        },
    }
}

fn fit_or_pad(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len >= width {
        return value.chars().take(width).collect();
    }
    let mut out = value.to_string();
    out.push_str(&" ".repeat(width - len));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::RunTraceStep;

    #[test]
    fn activity_plain_pane_rows_pads_cells_and_supplies_missing_side() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "reasoning", "thinking")
                .with_module_id("triage")
                .with_verb("run")
                .with_started_at_ms(42_000),
        );
        session.apply_step(
            RunTraceStep::new(2, "done", "complete")
                .with_module_id("verify")
                .with_verb("finding")
                .with_started_at_ms(43_000),
        );

        let rows = activity_plain_pane_rows(&session, 80, 20, Instant::now(), &[], None);

        assert!(rows.len() >= 3);
        assert_eq!(rows[0].separator, " │ ");
        assert_eq!(rows[0].dag.text.chars().count(), 80);
        assert_eq!(rows[0].feed.text.chars().count(), 20);
        assert_eq!(rows[0].feed.tone, None);
        assert!(rows.iter().any(|row| row.dag.text.contains("ACTIONS")));
        assert!(rows.iter().any(|row| row.dag.text.contains("[triage:run]")));
        assert!(rows
            .iter()
            .any(|row| row.dag.text.contains("[verify:finding]")));
        assert!(rows.iter().all(|row| row.feed.tone.is_none()));
    }

    #[test]
    fn activity_plain_pane_rows_append_pinned_generated_views() {
        let session = ActivitySession::new("r-1");
        let extra = [ActivityFeedPaneRow {
            text: "ATTACK PATH".to_string(),
            tone: ActivityFeedRowTone::Success,
        }];

        let rows = activity_plain_pane_rows(&session, 12, 20, Instant::now(), &extra, None);

        assert!(rows.iter().any(|row| row.feed.text.contains("ATTACK PATH")));
    }
}
