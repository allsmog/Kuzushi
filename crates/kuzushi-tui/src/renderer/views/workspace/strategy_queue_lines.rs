use super::*;
use crate::ui_view_models::{strategy_queue_model, StrategyQueueModel, StrategyQueueRow};

pub(crate) fn strategy_queue_page_rows(app: &ShellApp) -> Option<usize> {
    strategy_queue_area(app).map(|area| usize::from(area.height).max(1))
}

pub(crate) fn strategy_queue_max_scroll(app: &ShellApp) -> Option<u16> {
    let area = strategy_queue_area(app)?;
    let max = strategy_queue_lines(app, area)
        .len()
        .saturating_sub(usize::from(area.height));
    Some(max.min(u16::MAX as usize) as u16)
}

fn strategy_queue_area(app: &ShellApp) -> Option<Rect> {
    if app.shell_view() != ShellView::StrategyQueue {
        return None;
    }
    let viewport = app.viewport();
    let primary =
        crate::renderer::primary_body_area(app, Rect::new(0, 0, viewport.columns, viewport.rows));
    Some(crate::ui_view_models::answers_layout(app, primary).workspace)
}

pub(crate) fn strategy_queue_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = strategy_queue_model(app);
    lines.push(blank());
    lines.push(divider(model.title, area.width));
    if app.inspected_strategy_id().is_none() {
        append_queue_receipt(&mut lines, &model, area.width);
    }
    append_strategy_queue_rows(&mut lines, &model, area.width);
    if app.inspected_strategy_id().is_some() {
        append_queue_receipt(&mut lines, &model, area.width);
    }
    lines.push(command_list_line(&model.commands, area.width as usize));
    lines
}

fn append_queue_receipt(lines: &mut Vec<Line<'static>>, model: &StrategyQueueModel, width: u16) {
    lines.extend(wrapped_field("summary", &model.summary, width));
    lines.extend(wrapped_field("review", "Regenerated suggestions are new drafts. Earlier decisions and outcomes remain attached to their original ids.", width));
    lines.extend(wrapped_field(
        "allowance",
        "Proposal approval does not approve a study or increase its allowance.",
        width,
    ));
    append_strategy_queue_details(lines, model, width);
}

fn append_strategy_queue_details(
    lines: &mut Vec<Line<'static>>,
    model: &StrategyQueueModel,
    width: u16,
) {
    for row in &model.detail_rows {
        lines.extend(wrapped_field(&row.cells[0], &row.cells[1], width));
    }
}

fn append_strategy_queue_rows(
    lines: &mut Vec<Line<'static>>,
    model: &StrategyQueueModel,
    width: u16,
) {
    if model.rows.is_empty() {
        let empty = &model.empty_state;
        lines.extend(empty_state_panel(
            empty.title,
            &empty.explanations,
            &empty.actions,
        ));
        return;
    }
    for proposal in &model.rows {
        lines.extend(strategy_queue_row_lines(proposal, width));
    }
}

fn strategy_queue_row_lines(proposal: &StrategyQueueRow, width: u16) -> Vec<Line<'static>> {
    let fields = [
        (
            "proposal",
            format!("{} · {}", proposal.cells[0], proposal.id),
        ),
        ("tool", proposal.tool.clone()),
        ("phase", proposal.cells[1].clone()),
        ("strategy", proposal.cells[3].clone()),
        (
            "yield / rounds",
            format!("{} / {}", proposal.cells[4], proposal.cells[5]),
        ),
        (
            "cost",
            format!(
                "estimated {} · approved {} · actual {}",
                proposal.cells[6], proposal.approved_cost, proposal.cells[7]
            ),
        ),
        ("outcome", proposal.cells[8].clone()),
        ("result run", proposal.result_run.clone()),
        ("source run", proposal.source_run.clone()),
        (
            "readiness",
            format!(
                "{} · runtime {} · risk {}",
                proposal.cells[9], proposal.cells[10], proposal.cells[11]
            ),
        ),
        ("lineage", proposal.lineage.clone()),
        ("why", proposal.rationale.clone()),
    ];
    let mut lines = vec![blank()];
    for (label, value) in fields {
        lines.extend(wrapped_field(label, &value, width));
    }
    lines.push(blank());
    lines
}

fn wrapped_field(label: &str, value: &str, width: u16) -> Vec<Line<'static>> {
    wrap_text(&format!("{label}: {value}"), usize::from(width).max(1))
        .into_iter()
        .map(|text| row(&[text]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_history_cards_preserve_full_identity_cost_and_outcome_at_all_widths() {
        let row = StrategyQueueRow {
            id: "review-context-build-draft-0123456789abcdef0123456789abcdef".into(),
            cells: [
                "done",
                "review",
                "id",
                "run context:build",
                "-",
                "-",
                "unknown",
                "$0.2000",
                "1/2 confirmed",
                "ready",
                "local pass",
                "low",
            ]
            .map(str::to_owned),
            rationale: "Owned historical receipt; not a real scanner outcome.".into(),
            lineage: "base -> recommended -> operator correction".into(),
            source_run: "owned-original-source-run".into(),
            approved_cost: "$0.5000".into(),
            result_run: "owned-recorded-result".into(),
            tool: "context:build".into(),
        };
        for width in [40, 60, 80, 96, 120, 160] {
            let lines = strategy_queue_row_lines(&row, width);
            assert!(lines
                .iter()
                .all(|line| display_width(&line.to_string()) <= usize::from(width)));
            let text = lines
                .iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("");
            assert!(text.contains(&row.id));
            let text = lines
                .iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(text.contains("approved $0.5000"));
            assert!(text.contains("actual $0.2000"));
            assert!(text.contains(&row.result_run));
        }
    }
}
