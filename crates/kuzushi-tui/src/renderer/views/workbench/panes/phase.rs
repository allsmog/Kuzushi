use super::*;
use crate::renderer::views::scene::diagrams::heatmap_lines;
use crate::ui_view_models::{
    cached_findings_heatmap, cached_risk_by_module, recommendation_model, ModuleRisk,
    RecommendationRow,
};
use kuzushi_core::engagement::{ENGAGEMENT_DIR, HARNESS_FILE};
use ratatui::prelude::{Line, Span};
use std::fs;

pub(in crate::renderer::views::workbench) fn terrain_attack_surface_lines(
    app: &ShellApp,
    width: usize,
) -> Vec<Line<'static>> {
    let risk = cached_risk_by_module(app);
    if risk.modules.is_empty() {
        return pane_empty_state(
            "no terrain yet",
            &["run map/hunt steps to populate module risk from findings."],
            &[("next", "open the guided workflow")],
        );
    }
    let mut lines = vec![Line::styled(
        fit("module risk from current findings", width),
        theme::muted(),
    )];
    lines.extend(risk.modules.iter().take(12).map(|module| {
        Line::from(vec![
            Span::styled("· ", theme::muted()),
            Span::styled(
                fit(&module.module, width.saturating_sub(28).max(8)),
                theme::label(),
            ),
            Span::raw(" "),
            Span::styled(risk_counts_label(module), theme::muted()),
            Span::raw(" "),
            Span::styled(format!("risk {:.0}", module.score), theme::warn()),
        ])
    }));
    lines.push(blank());
    lines.push(Line::styled(
        format!(
            "{} findings · {} modules",
            app.findings.len(),
            risk.modules.len()
        ),
        theme::muted(),
    ));
    lines
}

pub(in crate::renderer::views::workbench) fn terrain_visual_lines(
    app: &ShellApp,
    width: usize,
) -> Vec<Line<'static>> {
    heatmap_lines(width, &cached_findings_heatmap(app))
}

pub(in crate::renderer::views::workbench) fn terrain_material_lines(
    app: &ShellApp,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = harness_material_lines(app, width);
    lines.push(blank());
    lines.extend(recommendation_material_lines(app, width));
    lines.push(blank());
    lines.extend(seed_material_lines(app, width));
    lines
}

fn harness_material_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled("HARNESS", theme::accent())];
    let Some(target) = app.target.as_ref() else {
        lines.push(Line::styled("  no target selected", theme::muted()));
        lines.push(command_hint("target <path>", "select workspace", width));
        return lines;
    };
    let path = target.join(ENGAGEMENT_DIR).join(HARNESS_FILE);
    let Ok(body) = fs::read_to_string(&path) else {
        lines.push(Line::styled("  not seeded", theme::muted()));
        lines.push(command_hint("aim <focus>", "seed focus and engines", width));
        return lines;
    };
    lines.push(Line::styled(
        fit(&format!("  {}", harness_summary(&body)), width),
        theme::primary(),
    ));
    lines.push(command_hint("aim <focus>", "retune harness", width));
    lines
}

fn harness_summary(body: &str) -> String {
    let engines = body
        .lines()
        .filter(|line| line.trim() == "[[engines]]")
        .count();
    let focus = toml_string_value(body, "raw").unwrap_or_else(|| "none".to_string());
    let budget = toml_value(body, "budgetUsd")
        .or_else(|| toml_value(body, "budget_usd"))
        .map(|value| format!(" · budget ${value}"))
        .unwrap_or_default();
    format!("seeded · {engines} engines · focus {focus}{budget}")
}

fn toml_string_value(body: &str, key: &str) -> Option<String> {
    toml_value(body, key).map(|value| value.trim_matches('"').to_string())
}

fn toml_value(body: &str, key: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let (left, right) = line.split_once('=')?;
        (left.trim() == key).then(|| right.trim().to_string())
    })
}

fn recommendation_material_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let recommendations = recommendation_model(app);
    let mut lines = vec![Line::styled("RECOMMENDS", theme::accent())];
    if recommendations.rows.is_empty() {
        lines.extend(empty_recommendation_material_lines(width));
    } else {
        lines.extend(
            recommendations
                .rows
                .iter()
                .take(4)
                .flat_map(|row| recommendation_page_lines(row, width)),
        );
    }
    lines
}

fn empty_recommendation_material_lines(width: usize) -> Vec<Line<'static>> {
    vec![
        Line::styled("  no recommendations artifact yet", theme::muted()),
        command_hint("recommend", "rank modules for this workspace", width),
    ]
}

fn seed_material_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled("MATERIALS", theme::accent())];
    if app.kb_view.attachments.is_empty() {
        lines.extend(empty_seed_material_lines(width));
    } else {
        for record in app.kb_view.attachments.iter().take(5) {
            lines.push(Line::styled(
                fit(
                    &format!("  {}  {}  {}", record.id, record.status, record.source),
                    width,
                ),
                theme::primary(),
            ));
        }
    }
    lines
}

fn empty_seed_material_lines(width: usize) -> Vec<Line<'static>> {
    vec![
        Line::styled("  no seed materials attached", theme::muted()),
        command_hint("attach <path|url>", "add reference material", width),
    ]
}

fn recommendation_page_lines(row: &RecommendationRow, width: usize) -> Vec<Line<'static>> {
    let [priority, tool, runtime, signal, reason] = &row.cells;
    vec![
        Line::from(vec![
            Span::styled("· ", theme::muted()),
            Span::styled(fit(tool, width.saturating_sub(18).max(8)), theme::label()),
            Span::raw(" "),
            Span::styled(priority.clone(), theme::warn()),
        ]),
        Line::styled(
            fit(&format!("    {runtime} · {signal} · {reason}"), width),
            theme::muted(),
        ),
    ]
}

fn risk_counts_label(module: &ModuleRisk) -> String {
    let labels = ["C", "H", "M", "L", "I"];
    module
        .counts
        .iter()
        .zip(labels)
        .filter(|(count, _)| **count > 0)
        .map(|(count, label)| format!("{label}{count}"))
        .collect::<Vec<_>>()
        .join(" ")
}
