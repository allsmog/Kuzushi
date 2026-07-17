use super::*;
use crate::ui_view_models::{health_display_model, HealthDisplayModel};
use crate::{HealthFooter, HealthStatus};

pub(crate) fn health_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    health_model_lines(health_display_model(app), area.width as usize)
}

fn health_model_lines(model: HealthDisplayModel, width: usize) -> Vec<Line<'static>> {
    let HealthDisplayModel {
        status,
        body_rows,
        summary,
        footer,
    } = model;
    let mut lines = vec![
        health_status_line(&status, width),
        raw("─".repeat(width)),
        blank(),
    ];
    lines.extend(body_rows.into_iter().map(raw));
    lines.push(blank());
    lines.push(raw(" -- SUMMARY"));
    lines.push(raw(format!("   {summary}")));
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(health_footer_stage_line(width, &summary, &footer)));
    lines.push(raw(health_footer_keybind_line(&footer)));
    lines.push(raw(health_prompt_line(&footer)));
    lines
}

fn health_status_line(status: &HealthStatus, width: usize) -> Line<'static> {
    let full = format!(
        " KUZUSHI  target {}  ctx {}  model {}  module {}  cost {}",
        status.target, status.ctx, status.model, status.module, status.cost
    );
    if full.chars().count() <= width {
        return raw(full);
    }
    raw(fit(
        &format!(
            " KUZUSHI · target:{} · ctx:{} · model:{} · {} · {}",
            status.target, status.ctx, status.model, status.module, status.cost
        ),
        width,
    ))
}

fn health_footer_stage_line(width: usize, summary: &str, footer: &HealthFooter) -> String {
    let full_left = format!(" stage {summary} · routing direct");
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    if let Some(line) = aligned_footer_line(width, &full_left, &right) {
        return line;
    }
    let compact_left = format!(" stage {summary}");
    aligned_footer_line(width, &compact_left, &right).unwrap_or_else(|| {
        fit(
            &format!("{compact_left} · findings {}", footer.findings),
            width,
        )
    })
}

fn aligned_footer_line(width: usize, left: &str, right: &str) -> Option<String> {
    let used = left.chars().count() + right.chars().count();
    (used < width).then(|| format!("{left}{}{right}", " ".repeat(width - used)))
}

fn health_footer_keybind_line(footer: &HealthFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}

fn health_prompt_line(footer: &HealthFooter) -> String {
    match footer.prompt_module.as_deref() {
        Some(module) => format!(" kuzushi ({module})>"),
        None => " kuzushi>".to_string(),
    }
}

fn raw(value: impl Into<String>) -> Line<'static> {
    Line::raw(value.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_SUMMARY: &str = "health: 3 failing, 3 warning";
    const STALE_SUMMARY: &str = "health: 0 failing, 7 warning";

    #[test]
    fn health_lines_share_one_summary_and_truthful_context_at_operator_sizes() {
        for area in [Rect::new(0, 0, 100, 30), Rect::new(0, 0, 80, 24)] {
            let lines = health_model_lines(health_fixture(), area.width as usize);
            let rendered = lines
                .iter()
                .map(Line::to_string)
                .collect::<Vec<_>>()
                .join("\n");

            assert!(rendered.contains("ctx"));
            assert!(rendered.contains("not built"));
            assert!(!rendered.contains("ctx ✓ live"));
            assert_eq!(rendered.matches(CURRENT_SUMMARY).count(), 2);
            assert!(!rendered.contains(STALE_SUMMARY));
            assert!(lines.len() <= area.height as usize);
            assert!(lines
                .iter()
                .all(|line| line.to_string().chars().count() <= area.width as usize));
        }
    }

    fn health_fixture() -> HealthDisplayModel {
        HealthDisplayModel {
            status: HealthStatus {
                target: "./demo".to_string(),
                ctx: "not built".to_string(),
                model: "unconfigured".to_string(),
                module: "doctor".to_string(),
                cost: "$0.00".to_string(),
            },
            body_rows: vec![
                " --:--:--  ●  doctor".to_string(),
                " -- CURRENT PREFLIGHT".to_string(),
                "  ✗  credential env                 OPENAI_API_KEY=missing".to_string(),
            ],
            summary: CURRENT_SUMMARY.to_string(),
            footer: HealthFooter {
                stage: STALE_SUMMARY.to_string(),
                findings: 4,
                keybinds: vec![("/auth".to_string(), "login".to_string())],
                prompt_module: Some("doctor".to_string()),
            },
        }
    }
}
