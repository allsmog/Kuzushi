//! Attack path — a tainted value's journey from source to sink, drawn as a
//! left-to-right chain of stage boxes joined by arrows. Fed by the real
//! `taint-iris` flow; box widths scale to the available width and labels
//! truncate inside their box rather than spilling off-screen.

use super::*;
use crate::theme;
use crate::ui_view_models::TaintFlowPath;

/// Width of each inter-stage connector (`─▶ `). Kept small so the boxes fit.
const CONN: usize = 3;
/// Cap on stages drawn horizontally so the boxes stay readable on narrow widths.
const MAX_STAGES: usize = 4;

struct Stage {
    title: String,
    caption: String,
    sev: Sev,
}

pub(crate) fn attack_path_lines(width: usize, model: &TaintFlowPath) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return scene_empty_state_lines(
            "no taint flow",
            hint,
            &[("taint-iris:hunt", "generate a source-to-sink path")],
        );
    }
    let stages = build_stages(model);
    let box_w = (width.saturating_sub(2 + stages.len().saturating_sub(1) * CONN)
        / stages.len().max(1))
    .clamp(9, 20);
    let inner = box_w.saturating_sub(4);

    let mut lines = vec![
        line(vec![
            span("  taint flow   ", theme::label()),
            span(
                format!("{} · {}", model.cwe, model.severity),
                theme::primary(),
            ),
        ]),
        blank(),
    ];
    lines.extend(flow_rows(&stages, box_w, inner));
    lines.push(blank());
    lines.push(line(vec![
        span("  ", theme::muted()),
        span(format!("{} · ", model.cwe), theme::muted()),
        span(
            model.severity.to_uppercase(),
            sev_from_label(&model.severity).style(),
        ),
        span(
            format!(" · {}-stage source → sink flow", model.stages.len()),
            theme::muted(),
        ),
    ]));
    lines
}

fn build_stages(model: &TaintFlowPath) -> Vec<Stage> {
    let shown = model.stages.len().min(MAX_STAGES);
    let overall = sev_from_label(&model.severity);
    model
        .stages
        .iter()
        .take(MAX_STAGES)
        .enumerate()
        .map(|(i, stage)| Stage {
            title: stage.title.clone(),
            caption: stage.location.clone(),
            sev: stage_sev(i, shown, overall),
        })
        .collect()
}

/// Source is the entry (amber), the sink carries the finding's overall severity,
/// and intermediate hops are medium — so the eye lands on the ends.
fn stage_sev(index: usize, shown: usize, overall: Sev) -> Sev {
    if index == 0 {
        Sev::High
    } else if index + 1 == shown {
        overall
    } else {
        Sev::Medium
    }
}

fn sev_from_label(severity: &str) -> Sev {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" => Sev::Critical,
        "high" => Sev::High,
        "medium" | "med" => Sev::Medium,
        "low" => Sev::Low,
        _ => Sev::Info,
    }
}

/// Build the four rows (top border, title, bottom border, caption) of the boxed
/// flow, with arrows on the title row in the gaps.
fn flow_rows(stages: &[Stage], box_w: usize, inner: usize) -> Vec<Line<'static>> {
    let gap = " ".repeat(CONN);
    let arrow = format!("{}▶ ", "─".repeat(CONN.saturating_sub(2)));
    let bar = "─".repeat(box_w.saturating_sub(2));

    let mut top = vec![span("  ", theme::muted())];
    let mut title = vec![span("  ", theme::muted())];
    let mut bottom = vec![span("  ", theme::muted())];
    let mut caption = vec![span("  ", theme::muted())];

    for (i, stage) in stages.iter().enumerate() {
        let frame = stage.sev.style();
        top.push(span(format!("╭{bar}╮"), frame));
        title.push(span("│ ", frame));
        title.push(span(centered(&stage.title, inner), theme::heading()));
        title.push(span(" │", frame));
        bottom.push(span(format!("╰{bar}╯"), frame));
        caption.push(span(centered(&stage.caption, box_w), frame));

        if i + 1 < stages.len() {
            top.push(span(gap.clone(), theme::muted()));
            title.push(span(arrow.clone(), theme::accent()));
            bottom.push(span(gap.clone(), theme::muted()));
            caption.push(span(gap.clone(), theme::muted()));
        }
    }
    vec![line(top), line(title), line(bottom), line(caption)]
}
