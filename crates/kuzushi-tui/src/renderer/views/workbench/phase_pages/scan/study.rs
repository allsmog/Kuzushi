use super::*;
use crate::renderer::shared::text::wrap_text;
use crate::ui_view_models::ScanPhaseModel;

pub(super) fn plain_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = divider_lines("APPROVED STUDY", summary_lines(model, width), width);
    lines.extend(divider_lines(
        "TARGET / PLAN",
        scope_lines(model, width),
        width,
    ));
    lines.extend(divider_lines("STUDY JOBS", job_lines(model, width), width));
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
        wrap_text("Per-job scopes: c study jobs", width)
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
    lines.push(Line::styled(
        fit("c study jobs · queue at last read", width),
        theme::accent(),
    ));
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
    let Some(queue) = model.study.as_ref().and_then(|study| study.queue.as_ref()) else {
        return summary_lines(model, width);
    };
    super::content::engine_outcome_lines(&queue.jobs, width)
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
    lines.push(Line::styled(fit("c study jobs", width), theme::accent()));
    lines
}

#[cfg(test)]
mod tests;
