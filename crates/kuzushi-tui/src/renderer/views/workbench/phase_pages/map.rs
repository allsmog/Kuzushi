use super::*;
use crate::ui_view_models::{
    ActivityTaskCountModel, EngagementHeaderModel, MapArtifactMetric, MapConsoleRow, MapPhaseModel,
};

mod console;
mod telemetry;

use console::console_lines;
use telemetry::{task_count_line, telemetry_lines};

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &MapPhaseModel,
    header: &EngagementHeaderModel,
    state: PhaseRenderState,
) {
    let width = area.width.saturating_sub(2) as usize;
    let height = area.height.saturating_sub(1) as usize;
    render_lines_pane(
        frame,
        area,
        "MAP · RECON",
        map_lines(model, header, width, height),
        WorkbenchPane::Center,
        state,
    );
}

pub(super) fn plain_lines(
    model: &MapPhaseModel,
    header: &EngagementHeaderModel,
    width: usize,
) -> Vec<Line<'static>> {
    divider_lines(
        "MAP · RECON",
        map_lines(model, header, width, usize::MAX),
        width,
    )
}

fn map_lines(
    model: &MapPhaseModel,
    header: &EngagementHeaderModel,
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        operation_line(model, header, width),
        section_line("RECON", width),
    ];
    lines.extend(console_lines(
        model,
        width,
        console_row_budget(height, !model.artifact_metrics.is_empty()),
    ));
    lines.push(section_line("TELEMETRY", width));
    lines.extend(telemetry_lines(model, header, width));
    lines
}

fn operation_line(
    model: &MapPhaseModel,
    header: &EngagementHeaderModel,
    width: usize,
) -> Line<'static> {
    let state = if header.live {
        "● LIVE"
    } else {
        "○ settled"
    };
    let run = model
        .run_id
        .as_deref()
        .map(compact_run_id)
        .unwrap_or_else(|| "no run".to_string());
    let elapsed = model
        .elapsed_secs
        .map(|seconds| format!(" · {seconds}s"))
        .unwrap_or_default();
    Line::from(vec![
        Span::styled(format!(" {state} "), live_style(header.live)),
        Span::styled(
            fit(
                &format!("run {run}{elapsed} · {}", header.module),
                width.saturating_sub(9),
            ),
            theme::primary(),
        ),
    ])
}

fn live_style(live: bool) -> ratatui::style::Style {
    if live {
        theme::success()
    } else {
        theme::muted()
    }
}

fn compact_run_id(run_id: &str) -> String {
    let reference = crate::app::compact_run_reference(run_id);
    if reference == run_id {
        reference
    } else {
        format!("…{reference}")
    }
}

fn console_row_budget(height: usize, has_artifact_metrics: bool) -> usize {
    height
        .saturating_sub(8 + usize::from(has_artifact_metrics))
        .clamp(3, 24)
}

fn section_line(title: &str, width: usize) -> Line<'static> {
    divider(title, width as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_reference_is_copyable_eight_character_suffix() {
        assert_eq!(compact_run_id("scan-1234-abcdef12"), "…abcdef12");
        assert_eq!(compact_run_id("short"), "short");
    }

    #[test]
    fn compact_task_status_drops_whole_secondary_atoms() {
        let line = task_count_line(
            &ActivityTaskCountModel {
                active: 1,
                canceling: 2,
                failed: 3,
                blocked: 4,
                canceled: 5,
                skipped: 6,
                ..ActivityTaskCountModel::default()
            },
            38,
        );
        let text = line.to_string();

        assert!(line.width() <= 38);
        assert!(!text.contains('…'));
        assert!(!text.ends_with('·'));
    }
}
