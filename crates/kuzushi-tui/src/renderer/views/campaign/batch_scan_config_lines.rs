use super::*;
use crate::app::{BatchScanConfig, BatchScanConfigRow, BATCH_HARD_CAP, BATCH_REVIEW_THRESHOLD};

pub(super) fn append_batch_scan_config(
    lines: &mut Vec<Line<'static>>,
    config: &BatchScanConfig,
    area: Rect,
) {
    lines.push(divider("SCAN BATCH", area.width));
    lines.push(Line::styled(
        format!(
            "  repeat one canonical sast:scan input · review above {} · hard cap {}",
            BATCH_REVIEW_THRESHOLD, BATCH_HARD_CAP
        ),
        theme::subtle(),
    ));
    lines.push(blank());
    lines.extend(batch_config_rows(config));
    append_batch_cost_evidence(lines, config);
    append_batch_config_notice(lines, config);
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "j/k",
            "Enter change",
            "w workers",
            "L review/launch",
            "r refresh",
            "q campaigns",
        ],
        area.width as usize,
    ));
}

fn batch_config_rows(config: &BatchScanConfig) -> Vec<Line<'static>> {
    [
        (BatchScanConfigRow::Trials, config.trials.to_string()),
        (BatchScanConfigRow::Workers, workers_label(config)),
        (BatchScanConfigRow::PriorRun, prior_run_label(config)),
        (BatchScanConfigRow::Launch, launch_label(config)),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (row, value))| config_row_line(config, index, row, &value))
    .collect()
}

fn config_row_line(
    config: &BatchScanConfig,
    index: usize,
    row: BatchScanConfigRow,
    value: &str,
) -> Line<'static> {
    let selected = index == config.cursor;
    let marker = if selected { "▸" } else { " " };
    let style = if selected {
        theme::selection()
    } else {
        theme::primary()
    };
    Line::styled(format!("{marker} {:<22} {value}", row.label()), style)
}

fn workers_label(config: &BatchScanConfig) -> String {
    let workers = format!(
        "requested {} → effective {}",
        config.requested_workers, config.effective_workers
    );
    match config.worker_clamp_reason.as_deref() {
        Some(reason) => format!("{workers} · {reason}"),
        None => workers,
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
        return "reviewed · launch again to start detached dispatcher".to_string();
    }
    if config.needs_large_batch_review() {
        return "review required before detached launch".to_string();
    }
    "launch through detached campaign dispatcher".to_string()
}

fn append_batch_cost_evidence(lines: &mut Vec<Line<'static>>, config: &BatchScanConfig) {
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
        _ => "  cost not estimated — choose a named completed sast:scan prior run".to_string(),
    };
    lines.push(Line::styled(label, theme::subtle()));
}

fn append_batch_config_notice(lines: &mut Vec<Line<'static>>, config: &BatchScanConfig) {
    if let Some(notice) = &config.notice {
        lines.push(Line::styled(format!("  {notice}"), theme::warn()));
    }
}
