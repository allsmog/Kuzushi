use super::*;
use crate::ui_view_models::{strategy_queue_model, StrategyQueueRow};
use kuzushi_core::Finding;
use ratatui::prelude::{Line, Span};
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::renderer::views::workbench) fn hunt_control_lines(
    app: &ShellApp,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled("HUNT - proposal queue", theme::accent())];
    lines.push(engine_chips_line(app, width));
    lines.extend(hunt_budget_lines(app, width));
    lines.push(blank());
    lines.extend(strategy_proposal_lines(app, width));
    lines.push(blank());
    lines.extend(coverage_summary_lines(app, width));
    lines
}

fn engine_chips_line(app: &ShellApp, width: usize) -> Line<'static> {
    Line::styled(
        fit(
            &format!(
                "engines  {}   {}   {}",
                engine_chip(app, "cpg", ".kuzushi/cpg.bin"),
                engine_chip(app, "codeql", ".kuzushi/codeql-db"),
                "lsp ○ opt-in"
            ),
            width,
        ),
        theme::primary(),
    )
}

fn engine_chip(app: &ShellApp, label: &str, artifact: &str) -> String {
    if target_artifact_exists(app, artifact) {
        format!("{label} ✓ ready")
    } else {
        format!("{label} ○ build")
    }
}

fn target_artifact_exists(app: &ShellApp, relative: &str) -> bool {
    app.target()
        .map(|target| target.join(relative).exists())
        .unwrap_or(false)
}

fn hunt_budget_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let spent = app.session().session_cost_usd().max(0.0);
    let Some(cap) = app.session().session_budget_usd().filter(|cap| *cap > 0.0) else {
        return vec![Line::styled(
            fit(
                &format!("budget  no session cap · spent ${spent:.4}"),
                width,
            ),
            theme::muted(),
        )];
    };
    let ratio = (spent / cap).clamp(0.0, 1.0);
    vec![Line::from(vec![
        Span::styled("budget  ", theme::muted()),
        Span::styled(meter_bar(ratio, 12), budget_meter_style(ratio)),
        Span::raw(" "),
        Span::styled(format!("${spent:.2} / ${cap:.2}"), theme::primary()),
    ])]
}

fn meter_bar(ratio: f64, cells: usize) -> String {
    let filled = (ratio * cells as f64).round() as usize;
    let filled = filled.min(cells);
    format!("{}{}", "▓".repeat(filled), "░".repeat(cells - filled))
}

fn budget_meter_style(ratio: f64) -> ratatui::style::Style {
    if ratio >= 0.9 {
        theme::danger()
    } else if ratio >= 0.7 {
        theme::warn()
    } else {
        theme::accent()
    }
}

fn strategy_proposal_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let model = strategy_queue_model(app);
    if model.rows.is_empty() {
        let mut lines = pane_empty_state(
            "no proposals yet",
            &["run recommend to generate strategy proposals for this target."],
            &[
                ("recommend", "rank detectors and hunts"),
                ("strategy", "open the queue"),
            ],
        );
        lines.push(Line::styled(fit(&model.summary, width), theme::muted()));
        return lines;
    }
    let mut lines = vec![Line::styled(fit(&model.summary, width), theme::muted())];
    lines.extend(
        model
            .rows
            .iter()
            .take(8)
            .map(|row| proposal_row_line(row, width)),
    );
    lines
}

fn proposal_row_line(row: &StrategyQueueRow, width: usize) -> Line<'static> {
    let status = row.cells[0].as_str();
    let body = format!(
        "{} {}  {}  {} · yield {} · {}",
        proposal_marker(status),
        row.id,
        row.cells[3],
        row.cells[6],
        row.cells[4],
        row.cells[10]
    );
    Line::styled(fit(&body, width), proposal_style(status))
}

fn proposal_marker(status: &str) -> &'static str {
    match status {
        "approved" | "done" => "✓",
        "rejected" => "✗",
        "running" => "⠿",
        "failed" => "!",
        _ => "·",
    }
}

fn proposal_style(status: &str) -> ratatui::style::Style {
    match status {
        "approved" | "done" => theme::success(),
        "running" => theme::accent(),
        "failed" => theme::danger(),
        "rejected" => theme::muted(),
        _ => theme::primary(),
    }
}

fn coverage_summary_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let rows = coverage_rows(app.findings());
    if rows.is_empty() {
        return vec![command_hint(
            "scan",
            "fire the first hunt to populate coverage",
            width,
        )];
    }
    let mut lines = vec![Line::styled(
        "coverage from current ledger",
        theme::accent(),
    )];
    lines.extend(
        rows.into_iter()
            .take(5)
            .map(|row| coverage_line(row, width)),
    );
    lines
}

#[derive(Debug, Clone)]
struct CoverageRow {
    module: String,
    tools: BTreeMap<String, usize>,
    findings: usize,
    scans: usize,
    duplicates: usize,
}

fn coverage_rows(findings: &[Finding]) -> Vec<CoverageRow> {
    let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        groups
            .entry(coverage_module(&finding.file_path))
            .or_default()
            .push(finding);
    }
    let mut rows = groups
        .into_iter()
        .map(|(module, findings)| coverage_row(module, findings))
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        b.findings
            .cmp(&a.findings)
            .then_with(|| a.module.cmp(&b.module))
    });
    rows
}

fn coverage_row(module: String, findings: Vec<&Finding>) -> CoverageRow {
    let mut tools = BTreeMap::new();
    let mut scans = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    for finding in &findings {
        *tools.entry(finding.tool.clone()).or_insert(0) += 1;
        if let Some(scan_id) = &finding.scan_id {
            scans.insert(scan_id.clone());
        }
        fingerprints.insert(finding.fingerprint.clone());
    }
    let findings_len = findings.len();
    CoverageRow {
        module,
        tools,
        findings: findings_len,
        scans: scans.len(),
        duplicates: findings_len.saturating_sub(fingerprints.len()),
    }
}

fn coverage_module(path: &str) -> String {
    let mut parts = path.split('/').filter(|part| !part.is_empty());
    parts.next().unwrap_or("(root)").to_string()
}

fn coverage_line(row: CoverageRow, width: usize) -> Line<'static> {
    let scans = if row.scans > 1 {
        format!(" ×{} scans", row.scans)
    } else {
        String::new()
    };
    Line::styled(
        fit(
            &format!(
                "{:<24} {:<36} {:>8} {:>8}{}",
                row.module,
                coverage_tools_label(&row.tools),
                row.findings,
                row.duplicates,
                scans
            ),
            width,
        ),
        theme::primary(),
    )
}

fn coverage_tools_label(tools: &BTreeMap<String, usize>) -> String {
    tools
        .iter()
        .take(5)
        .map(|(tool, count)| format!("{}:{count}", short_tool(tool)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn short_tool(tool: &str) -> &str {
    tool.rsplit(':').next().unwrap_or(tool)
}
