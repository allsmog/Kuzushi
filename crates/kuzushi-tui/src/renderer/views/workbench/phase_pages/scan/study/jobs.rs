//! Keep recorded job labels readable before displaying optional references.
use super::super::format::{outcome_style, outcome_symbol};
use super::*;
use crate::ui_view_models::ScanEngineOutcomeModel;

pub(super) fn lines(
    jobs: &[ScanEngineOutcomeModel],
    width: usize,
    include_references: bool,
) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }
    jobs.iter()
        .flat_map(|job| job_lines(job, width, include_references))
        .collect()
}

fn job_lines(
    job: &ScanEngineOutcomeModel,
    width: usize,
    include_references: bool,
) -> Vec<Line<'static>> {
    let mut lines = label_lines(job, width);
    if include_references {
        if let Some(reference) = &job.run_ref {
            lines.extend(indented_lines(&format!("Run: {reference}"), width));
        }
    }
    if let Some(reason) = &job.detail {
        lines.extend(indented_lines(reason, width));
    }
    lines
}

fn label_lines(job: &ScanEngineOutcomeModel, width: usize) -> Vec<Line<'static>> {
    let text = format!("{} · {}", job.engine, job.outcome);
    wrap_text(&text, width.saturating_sub(2).max(1))
        .into_iter()
        .enumerate()
        .map(|(index, text)| {
            let prefix = if index == 0 {
                format!("{} ", outcome_symbol(&job.outcome))
            } else {
                "  ".into()
            };
            let prefix = fit(&prefix, width);
            let remaining = width.saturating_sub(display_width(&prefix));
            Line::from(vec![
                Span::styled(prefix, outcome_style(&job.outcome)),
                Span::styled(fit(&text, remaining), theme::primary()),
            ])
        })
        .collect()
}

fn indented_lines(text: &str, width: usize) -> Vec<Line<'static>> {
    wrap_text(text, width.saturating_sub(2).max(1))
        .into_iter()
        .map(|text| Line::styled(fit(&format!("  {text}"), width), theme::muted()))
        .collect()
}
