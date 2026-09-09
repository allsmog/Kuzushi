use super::*;
use crate::app::{BatchScanConfig, BatchScanConfigRow, BATCH_HARD_CAP, BATCH_REVIEW_THRESHOLD};

pub(super) fn append_batch_scan_config(
    lines: &mut Vec<Line<'static>>,
    config: &BatchScanConfig,
    area: Rect,
) {
    lines.push(divider("SCAN BATCH", area.width));
    if config.number_edit.is_some() {
        append_number_editor(lines, config, area);
        return;
    }
    append_batch_text(
        lines,
        &format!(
            "Repeat the same scan · review above {} trials · maximum {}",
            BATCH_REVIEW_THRESHOLD, BATCH_HARD_CAP
        ),
        area.width,
        theme::subtle(),
    );
    lines.push(blank());
    lines.extend(batch_config_rows(config, area.width));
    append_batch_worker_policy(lines, config, area.width);
    append_batch_cost_evidence(lines, config, area.width);
    append_batch_config_notice(lines, config, area.width);
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "j/k",
            "Enter edit",
            "w workers",
            "L review/launch",
            "r refresh",
            "q campaigns",
        ],
        area.width as usize,
    ));
}

fn batch_config_rows(config: &BatchScanConfig, width: u16) -> Vec<Line<'static>> {
    [
        (BatchScanConfigRow::Trials, config.trials.to_string()),
        (BatchScanConfigRow::Workers, workers_label(config)),
        (BatchScanConfigRow::PriorRun, prior_run_label(config)),
        (BatchScanConfigRow::Launch, launch_label(config)),
    ]
    .into_iter()
    .enumerate()
    .flat_map(|(index, (row, value))| config_row_lines(config, index, row, &value, width))
    .collect()
}

fn config_row_lines(
    config: &BatchScanConfig,
    index: usize,
    row: BatchScanConfigRow,
    value: &str,
    width: u16,
) -> Vec<Line<'static>> {
    let selected = index == config.cursor;
    let marker = if selected { "▸" } else { " " };
    let style = if selected {
        theme::selection()
    } else {
        theme::primary()
    };
    config_value_lines(
        &format!("{marker} {:<22} ", row.label()),
        value,
        width as usize,
        style,
    )
}

fn config_value_lines(
    prefix: &str,
    value: &str,
    width: usize,
    style: ratatui::style::Style,
) -> Vec<Line<'static>> {
    if width < 40 {
        return wrap_text(&format!("{prefix}{value}"), width)
            .into_iter()
            .map(|line| Line::styled(line, style))
            .collect();
    }
    let indent = prefix.chars().count();
    wrap_text(value, width.saturating_sub(indent).max(1))
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let prefix = if index == 0 {
                prefix.to_string()
            } else {
                " ".repeat(indent)
            };
            Line::styled(format!("{prefix}{chunk}"), style)
        })
        .collect()
}

fn workers_label(config: &BatchScanConfig) -> String {
    format!(
        "requested {} · using {}",
        config.requested_workers, config.effective_workers
    )
}

fn append_batch_worker_policy(
    lines: &mut Vec<Line<'static>>,
    config: &BatchScanConfig,
    width: u16,
) {
    if let Some(reason) = &config.worker_clamp_reason {
        lines.push(blank());
        append_batch_text(
            lines,
            &format!("Worker limit: {reason}"),
            width,
            theme::warn(),
        );
    }
}

fn prior_run_label(config: &BatchScanConfig) -> String {
    match (config.prior_run_id.as_deref(), config.prior_run_cost_usd) {
        (Some(run_id), Some(cost)) => format!("{run_id} · ${cost:.4}/trial"),
        _ => "not selected — projection withheld".to_string(),
    }
}

fn launch_label(config: &BatchScanConfig) -> String {
    if config.review_armed {
        return "reviewed · launch again to start in the background".to_string();
    }
    if config.needs_large_batch_review() {
        return "review required before starting".to_string();
    }
    "start this batch in the background".to_string()
}

fn append_batch_cost_evidence(
    lines: &mut Vec<Line<'static>>,
    config: &BatchScanConfig,
    width: u16,
) {
    lines.push(blank());
    let label = match (
        config.prior_run_id.as_deref(),
        config.prior_run_cost_usd,
        config.projected_cost_usd(),
    ) {
        (Some(run_id), Some(per_trial), Some(total)) => format!(
            "  historical projection ${total:.4} = ${per_trial:.4} × {} trials · prior run {run_id} · not a guarantee",
            config.trials
        ),
        _ => "  cost not estimated — choose a completed scan with a recorded cost".to_string(),
    };
    append_batch_text(lines, &label, width, theme::subtle());
}

fn append_batch_config_notice(
    lines: &mut Vec<Line<'static>>,
    config: &BatchScanConfig,
    width: u16,
) {
    if let Some(notice) = &config.notice {
        append_batch_text(lines, notice, width, theme::warn());
    }
}

fn append_number_editor(lines: &mut Vec<Line<'static>>, config: &BatchScanConfig, area: Rect) {
    let Some(edit) = &config.number_edit else {
        return;
    };
    let (minimum, maximum) = edit.bounds();
    let current = match edit.row {
        BatchScanConfigRow::Trials => config.trials,
        _ => config.requested_workers,
    };
    lines.push(blank());
    let instructions = format!(
        "{} · current {current} · enter {minimum}–{maximum}",
        edit.row.label()
    );
    append_batch_text(lines, &instructions, area.width, theme::primary());
    append_batch_text(
        lines,
        "Enter saves · Esc cancels · saving does not start work",
        area.width,
        theme::subtle(),
    );
    lines.push(blank());
    lines.extend(field_editor_lines(&edit.field, area.width as usize, 3));
    if let Some(error) = &edit.error {
        lines.push(blank());
        append_batch_text(lines, error, area.width, theme::danger());
    }
}

fn append_batch_text(
    lines: &mut Vec<Line<'static>>,
    text: &str,
    width: u16,
    style: ratatui::style::Style,
) {
    lines.extend(
        wrap_text(text, width as usize)
            .into_iter()
            .map(|line| Line::styled(line, style)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_keeps_worker_policy_and_named_cost_evidence_readable() {
        let target = tempfile::tempdir().unwrap();
        let mut config = BatchScanConfig::load(target.path(), None);
        let reason = "parallel work is limited because this selected scan includes a scanner that shares its database";
        config.worker_clamp_reason = Some(reason.into());
        config.prior_run_id = Some("run-with-a-complete-recorded-cost".into());
        config.prior_run_cost_usd = Some(0.25);
        for width in [60, 80, 120] {
            let mut lines = Vec::new();
            append_batch_scan_config(&mut lines, &config, Rect::new(0, 0, width, 24));
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            assert!(text.contains(reason));
            assert!(text.contains("run-with-a-complete-recorded-cost"));
            assert!(text.contains("historical projection $0.7500"));
            assert!(text.contains("not a guarantee"));
            assert!(lines.iter().all(|line| line.width() <= width as usize));
        }
    }

    #[test]
    fn numeric_editor_keeps_value_bounds_and_controls_at_ordinary_widths() {
        let target = tempfile::tempdir().unwrap();
        let mut config = BatchScanConfig::load(target.path(), None);
        config.begin_number_edit(BatchScanConfigRow::Trials);
        config.number_edit.as_mut().unwrap().field.insert("50");
        for width in [60, 80, 120] {
            let mut lines = Vec::new();
            append_batch_scan_config(&mut lines, &config, Rect::new(0, 0, width, 16));
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("current 3"));
            assert!(text.contains("2–50"));
            assert!(text.contains("Enter saves"));
            assert!(text.contains("Esc cancels"));
            assert!(lines.iter().any(|line| line.to_string().trim() == "50"));
            assert!(lines.len() <= 16);
            assert!(lines.iter().all(|line| line.width() <= width as usize));
        }
    }
}
