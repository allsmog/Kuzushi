use super::*;
use crate::ui_view_models::{recommendation_model, RecommendationModel, RecommendationRow};

pub(crate) fn recommend_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = recommendation_model(app);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("RECOMMEND", area.width));

    lines.push(detail("recommendations", &model.source_detail));
    if let Some(run_id) = &model.run_id {
        lines.push(detail("run", run_id));
    }
    if let Some(surface) = &model.attack_surface {
        lines.push(attack_surface_risk_line(surface, area.width));
    }
    lines.push(blank());

    if model.recommendations.is_empty() {
        append_empty_recommendations(lines, area)
    } else {
        append_report(lines, &model, area)
    }
}

fn append_report(
    mut lines: Vec<Line<'static>>,
    model: &RecommendationModel,
    area: Rect,
) -> Vec<Line<'static>> {
    if let Some(summary) = &model.summary {
        lines.push(muted(&fit(&summary, area.width as usize)));
        lines.push(blank());
    }
    lines.push(aligned_header(
        &["pri", "tool", "runtime", "reason"],
        &[6, 26, 8, value_width(area, 48)],
    ));
    let take = (area.height.saturating_sub(10) as usize).max(4);
    for recommendation in model.recommendations.iter().take(take) {
        lines.push(recommendation_row(recommendation, area.width));
    }
    lines.push(blank());
    lines.push(command_list_line(
        &["run <tool> [json]", "trace <run>", "runs", "back"],
        area.width as usize,
    ));
    lines
}

fn append_empty_recommendations(mut lines: Vec<Line<'static>>, area: Rect) -> Vec<Line<'static>> {
    lines.extend(empty_state_panel(
        "no recommendations artifact",
        &[
            "recommend reads the latest recommendations.json artifact.",
            "generate it through normal tool dispatch when planning is needed.",
        ],
        &[
            (
                "run module-recommender:recommend",
                "writes recommendations.json",
            ),
            ("runs", "inspect persisted runs"),
        ],
    ));
    lines.push(command_list_line(
        &["run module-recommender:recommend", "runs", "back"],
        area.width as usize,
    ));
    lines
}

fn recommendation_row(recommendation: &RecommendationRow, width: u16) -> Line<'static> {
    let priority = recommendation.priority.as_deref().unwrap_or("low");
    let runtime = if recommendation.requires_runtime {
        "yes"
    } else {
        "no"
    };
    let reason_width = (width as usize).saturating_sub(44).max(24);
    row(&[
        pad(priority_glyph(priority), 6),
        pad(&recommendation.tool, 26),
        pad(runtime, 8),
        fit(&recommendation.reason, reason_width),
    ])
}

fn priority_glyph(priority: &str) -> &'static str {
    match priority {
        "high" => "⚠ high",
        "medium" => "◆ med",
        _ => "○ low",
    }
}
