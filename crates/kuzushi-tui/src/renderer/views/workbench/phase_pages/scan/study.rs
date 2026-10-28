use super::*;
use crate::renderer::shared::text::wrap_text;
use crate::ui_view_models::ScanPhaseModel;

mod jobs;

pub(super) fn plain_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = divider_lines("APPROVED STUDY", summary_lines(model, width), width);
    lines.extend(divider_lines(
        "TARGET / PLAN",
        scope_lines(model, width),
        width,
    ));
    lines.extend(divider_lines(
        "STUDY JOBS",
        job_lines_with_references(model, width, true),
        width,
    ));
    lines.extend(divider_lines(
        "RECORDED RESULT",
        super::content::receipt_lines(model, width),
        width,
    ));
    lines
}

pub(super) fn scope_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(study) = &model.study else {
        return Vec::new();
    };
    let mut lines = wrap_text(&format!("Target {}", study.target), width)
        .into_iter()
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    lines.extend(
        wrap_text(
            &format!("Per-job scopes: {} study jobs", study.jobs_key),
            width,
        )
        .into_iter()
        .map(|line| Line::styled(line, theme::accent())),
    );
    lines
}

pub(super) fn summary_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(study) = &model.study else {
        return Vec::new();
    };
    let rows = study.queue.as_ref().map_or_else(
        || {
            let label = study
                .issue
                .as_ref()
                .map_or("Reading study queue", |_| "Study queue unavailable");
            wrap_text(label, width)
        },
        |queue| queue_lines(queue, width),
    );
    let mut lines = rows
        .into_iter()
        .map(|line| Line::styled(line, theme::warn()))
        .collect::<Vec<_>>();
    lines.extend(
        wrap_text(
            &format!(
                "{} study jobs / run refs · queue at last read",
                study.jobs_key
            ),
            width,
        )
        .into_iter()
        .map(|line| Line::styled(line, theme::accent())),
    );
    if let Some(issue) = &study.issue {
        lines.extend(
            wrap_text(issue, width)
                .into_iter()
                .map(|line| Line::styled(line, theme::danger())),
        );
    }
    lines
}

fn queue_parts(queue: &crate::ui_view_models::ScanStudyQueue) -> Vec<String> {
    let mut parts = vec![format!("{}/{} complete", queue.completed, queue.jobs.len())];
    parts.extend(
        [
            (queue.running, "running"),
            (queue.queued, "queued"),
            (queue.failed, "failed"),
            (queue.deferred, "deferred"),
            (queue.unknown, "unknown"),
        ]
        .into_iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, state)| format!("{count} {state}")),
    );
    parts
}

fn queue_lines(queue: &crate::ui_view_models::ScanStudyQueue, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for part in queue_parts(queue) {
        append_count_part(&mut lines, &part, width);
    }
    lines
}

fn append_count_part(lines: &mut Vec<String>, part: &str, width: usize) {
    if let Some(last) = lines.last_mut() {
        let joined = format!("{last} · {part}");
        if display_width(&joined) <= width {
            *last = joined;
            return;
        }
    }
    lines.push(fit(part, width));
}

pub(super) fn job_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    job_lines_with_references(model, width, false)
}

fn job_lines_with_references(
    model: &ScanPhaseModel,
    width: usize,
    include_references: bool,
) -> Vec<Line<'static>> {
    let Some(queue) = model.study.as_ref().and_then(|study| study.queue.as_ref()) else {
        return summary_lines(model, width);
    };
    jobs::lines(&queue.jobs, width, include_references)
}

pub(super) fn receipt_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(study) = &model.study else {
        return Vec::new();
    };
    let mut lines = wrap_text(&format!("Study {}", study.campaign_id), width)
        .into_iter()
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    lines.extend(
        wrap_text("Select the completed study result before advancing.", width)
            .into_iter()
            .map(|line| Line::styled(line, theme::muted())),
    );
    lines.push(Line::styled(
        fit(&format!("{} study jobs", study.jobs_key), width),
        theme::accent(),
    ));
    lines
}

pub(super) fn result_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(attempt) = &model.attempt else {
        return receipt_lines(model, width);
    };
    let mut lines = result_status_lines(attempt, width);
    let jobs_key = model.study.as_ref().map_or('c', |study| study.jobs_key);
    lines.extend(
        wrap_text(
            &format!(
                "{} run references · {jobs_key} study jobs",
                attempt.run_refs.len()
            ),
            width,
        )
        .into_iter()
        .map(|line| Line::styled(line, theme::accent())),
    );
    lines.extend(super::format::receipt_metrics_lines(model, attempt, width));
    if let Some(error) = &attempt.error {
        lines.extend(
            wrap_text(error, width)
                .into_iter()
                .map(|line| Line::styled(line, theme::danger())),
        );
    }
    lines
}

fn result_status_lines(
    attempt: &crate::ui_view_models::ScanAttemptModel,
    width: usize,
) -> Vec<Line<'static>> {
    let status = format!("outcome {} · {}", attempt.outcome, attempt.freshness);
    let disposition = format!("result {}", attempt.disposition);
    [
        (&status, super::format::outcome_style(&attempt.outcome)),
        (
            &disposition,
            super::format::disposition_style(&attempt.disposition),
        ),
    ]
    .into_iter()
    .flat_map(|(text, style)| {
        wrap_text(text, width)
            .into_iter()
            .map(move |line| Line::styled(line, style))
    })
    .collect()
}

#[cfg(test)]
mod tests;
