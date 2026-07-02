//! Pure pane-body line builders for the Workbench command center. Shared by the
//! frame renderer (each list drawn inside a bordered `Block`) and the plain
//! `workbench_lines` path (each list stacked under a text divider).

use super::*;
use crate::renderer::views::scene::diagrams::{attack_path_lines, heatmap_lines};
use crate::ui_view_models::{
    attack_tree, findings_heatmap_with_selection, recommendation_model, risk_by_module,
    selected_taint_flow_path, threat_dfd_view, AttackTree, CleanScanEmptyState, CodePaneModel,
    CodePaneRow, DfdLineKind, FindingListRow, FindingsEmptyState, FindingsModel, ModuleRisk,
    ProofTier, RecommendationRow, SeverityTone, SourceTreeComponentTier, SourceTreeModel,
    SourceTreeRow, WorkbenchCenter, WorkbenchCenterBody, WORKBENCH_REPORT_COMMAND,
};
use kuzushi_core::{Finding, PersistedProofVerdict};
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Span};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn sep() -> Span<'static> {
    Span::styled(theme::STATUS_SEPARATOR, theme::subtle())
}

fn pane_empty_state(
    glyph_label: &str,
    explanations: &[&str],
    ctas: &[(&str, &str)],
) -> Vec<Line<'static>> {
    empty_state_panel(glyph_label, explanations, ctas)
}

// ── SOURCE pane ──────────────────────────────────────────────────────────────

pub(super) fn source_title(model: &SourceTreeModel) -> String {
    format!("SOURCE · {} files", model.file_count)
}

pub(super) fn source_pane_lines(model: &SourceTreeModel, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = model.empty_hint {
        return pane_empty_state(
            "no source tree",
            &[hint],
            &[("scan", "populate finding-bearing files")],
        );
    }
    model
        .rows
        .iter()
        .map(|row| source_row_line(row, width))
        .collect()
}

fn source_row_line(row: &SourceTreeRow, width: usize) -> Line<'static> {
    let indent = " ".repeat(row.depth * 2);
    let name = if row.is_dir {
        format!("{}/", row.name)
    } else {
        row.name.clone()
    };
    let name_style = if row.is_dir {
        theme::label()
    } else {
        theme::primary()
    };
    let count = source_count_label(row);
    let component = source_component_label(row);
    let Some(name) = fitted_source_name(&indent, component.as_deref(), &name, &count, width) else {
        return Line::from(Span::styled(
            fit(
                &format!("{indent}{}{name}{count}", component.unwrap_or_default()),
                width,
            ),
            name_style,
        ));
    };
    let mut spans = vec![Span::raw(indent)];
    if let Some(component) = source_component_label(row) {
        spans.push(Span::styled(component, source_component_style(row)));
    }
    spans.push(Span::styled(name, name_style));
    if !count.is_empty() {
        spans.push(Span::styled(count, theme::muted()));
    }
    Line::from(spans)
}

fn source_count_label(row: &SourceTreeRow) -> String {
    if row.finding_count > 0 {
        format!("  · {}", row.finding_count)
    } else {
        String::new()
    }
}

fn source_component_label(row: &SourceTreeRow) -> Option<String> {
    row.component
        .as_ref()
        .map(|component| format!("◆ {} ", component.label))
}

fn source_component_style(row: &SourceTreeRow) -> ratatui::style::Style {
    match row.component.as_ref().map(|component| component.tier) {
        Some(SourceTreeComponentTier::High) => theme::warn(),
        Some(SourceTreeComponentTier::Medium) => theme::accent(),
        _ => theme::muted(),
    }
}

fn fitted_source_name(
    indent: &str,
    component: Option<&str>,
    name: &str,
    count: &str,
    width: usize,
) -> Option<String> {
    let fixed_width = indent.chars().count()
        + component.unwrap_or_default().chars().count()
        + count.chars().count();
    let name_width = width.checked_sub(fixed_width)?;
    (name_width > 0).then(|| fit(name, name_width))
}

// ── PHASE pages ──────────────────────────────────────────────────────────────

pub(super) fn terrain_attack_surface_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let risk = risk_by_module(&app.findings);
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
            Span::styled("▸ ", theme::accent()),
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

pub(super) fn terrain_visual_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    heatmap_lines(width, &findings_heatmap_with_selection(&app.findings, None))
}

pub(super) fn terrain_material_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let mut lines = recommendation_material_lines(app, width);
    lines.push(blank());
    lines.extend(seed_material_lines(app, width));
    lines
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
            Span::styled("▸ ", theme::accent()),
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

pub(super) fn coverage_matrix_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let rows = coverage_rows(&app.findings);
    if rows.is_empty() {
        return pane_empty_state(
            "no coverage yet",
            &["run scanners to compare modules, tools, and repeated scans."],
            &[("scan", "run the guided hunt workflow")],
        );
    }
    let mut lines = vec![coverage_header(width)];
    lines.extend(
        rows.into_iter()
            .take(18)
            .map(|row| coverage_line(row, width)),
    );
    lines.push(blank());
    lines.push(Line::styled(
        "D shows these clusters without hiding distinct sinks; cross-scan duplicates keep their ×N badge.",
        theme::muted(),
    ));
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

fn coverage_header(width: usize) -> Line<'static> {
    Line::styled(
        fit(
            &format!(
                "{:<24} {:<36} {:>8} {:>8}",
                "module", "tools", "findings", "dupes"
            ),
            width,
        ),
        theme::label(),
    )
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

pub(super) fn ship_chain_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    chain_pane_lines(app, attack_tree(app).empty_hint.as_deref(), width)
}

pub(super) fn ship_patch_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let patchable = app
        .findings
        .iter()
        .filter(|finding| {
            finding.verification.as_ref().is_some_and(|verification| {
                verification.proof_verdict == PersistedProofVerdict::Exploited
            })
        })
        .take(8)
        .collect::<Vec<_>>();
    if patchable.is_empty() {
        return pane_empty_state(
            "no patch queue",
            &["only empirically verified findings enter the patch queue."],
            &[("v", "validate selected finding with verify:exploit")],
        );
    }
    patchable
        .into_iter()
        .map(|finding| {
            Line::styled(
                fit(
                    &format!(
                        "{}  {}  patchable",
                        finding.fingerprint,
                        finding.severity.as_str()
                    ),
                    width,
                ),
                theme::primary(),
            )
        })
        .collect()
}

pub(super) fn ship_export_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    vec![
        Line::styled("workspace export findings", theme::accent()),
        command_hint(WORKBENCH_REPORT_COMMAND, "SARIF report", width),
        command_hint(
            "workspace export findings report.md",
            "markdown bundle",
            width,
        ),
        blank(),
        Line::styled(
            fit(
                &format!("{} findings ready for export", app.findings.len()),
                width,
            ),
            theme::muted(),
        ),
    ]
}

fn command_hint(command: &str, label: &str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled("  ▸ ", theme::accent()),
        Span::styled(
            fit(command, width.saturating_sub(label.len() + 8).max(8)),
            theme::label(),
        ),
        Span::raw("  "),
        Span::styled(label.to_string(), theme::muted()),
    ])
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

// ── CENTER pane ──────────────────────────────────────────────────────────────

pub(super) fn center_pane_lines(
    app: &ShellApp,
    center: &WorkbenchCenter,
    width: usize,
) -> Vec<Line<'static>> {
    match &center.body {
        WorkbenchCenterBody::Code(Some(code)) => code_pane_lines(code, width),
        WorkbenchCenterBody::Code(None) => code_empty_lines(),
        WorkbenchCenterBody::Dfd { empty_hint } => {
            dfd_pane_lines(app, empty_hint.as_deref(), width)
        }
        WorkbenchCenterBody::Chain { empty_hint } => {
            chain_pane_lines(app, empty_hint.as_deref(), width)
        }
        WorkbenchCenterBody::Flow { .. } => {
            attack_path_lines(width, &selected_taint_flow_path(app))
        }
        WorkbenchCenterBody::Risk { .. } => heatmap_lines(
            width,
            &findings_heatmap_with_selection(&app.findings, app.selected_finding.as_ref()),
        ),
    }
}

fn code_empty_lines() -> Vec<Line<'static>> {
    pane_empty_state(
        "no finding selected",
        &["select a finding to show source context."],
        &[
            ("scan", "populate findings"),
            ("open <id>", "pin a finding"),
        ],
    )
}

fn dfd_pane_lines(app: &ShellApp, empty_hint: Option<&str>, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = empty_hint {
        return pane_empty_state(
            "no data-flow diagram",
            &[hint],
            &[("threat-model:build", "map trust zones and flows")],
        );
    }
    match threat_dfd_view(app, width.max(8)) {
        Some(diagram) => diagram.into_iter().map(dfd_line).collect(),
        None => pane_empty_state(
            "no data-flow nodes",
            &["threat model present but has no data-flow nodes."],
            &[("threat-model:build", "refresh the data-flow model")],
        ),
    }
}

fn chain_pane_lines(app: &ShellApp, empty_hint: Option<&str>, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = empty_hint {
        return pane_empty_state(
            "no exploit chain",
            &[hint],
            &[("exploit-chain:scan", "build entry-to-impact chains")],
        );
    }
    chain_tree_lines(&attack_tree(app), width)
}

fn chain_tree_lines(model: &AttackTree, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![Span::styled(
        format!("ATTACK TREE · {} chains", model.chains.len()),
        theme::accent(),
    )])];
    for (index, chain) in model.chains.iter().enumerate() {
        lines.push(Line::from(vec![Span::styled(
            fit(
                &format!(
                    "  {}. [{}] {}",
                    index + 1,
                    chain.severity.label(),
                    chain.title
                ),
                width,
            ),
            theme::primary(),
        )]));
        lines.extend(chain.steps.iter().enumerate().map(|(step_index, step)| {
            Line::from(vec![Span::styled(
                fit(&format!("      {}. {}", step_index + 1, step), width),
                theme::muted(),
            )])
        }));
    }
    lines
}

fn code_pane_lines(code: &CodePaneModel, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = &code.empty_hint {
        return pane_empty_state(
            "source unavailable",
            &[hint],
            &[("open <id>", "select another finding with source context")],
        );
    }
    code.rows
        .iter()
        .map(|row| code_row_line(row, width))
        .collect()
}

fn code_row_line(row: &CodePaneRow, width: usize) -> Line<'static> {
    let code_budget = width.saturating_sub(10).max(8);
    let style = code_row_style(row);
    Line::from(vec![
        Span::styled(code_row_marker(row), style),
        Span::raw(" "),
        Span::styled(format!("{:>4}", row.number), theme::subtle()),
        Span::styled(" │ ", theme::subtle()),
        Span::styled(fit(&row.text, code_budget), style),
    ])
}

fn code_row_marker(row: &CodePaneRow) -> &'static str {
    if row.highlighted {
        "▶"
    } else if row.evidence {
        "•"
    } else {
        " "
    }
}

fn code_row_style(row: &CodePaneRow) -> ratatui::style::Style {
    if row.highlighted {
        theme::warn()
    } else if row.evidence {
        theme::accent()
    } else {
        theme::primary()
    }
}

fn dfd_line(line: crate::ui_view_models::DfdDiagramLine) -> Line<'static> {
    Line::from(Span::styled(line.text, dfd_style(line.kind)))
}

fn dfd_style(kind: DfdLineKind) -> ratatui::style::Style {
    match kind {
        DfdLineKind::Title | DfdLineKind::Zone => theme::accent(),
        DfdLineKind::Boundary => theme::warn(),
        DfdLineKind::Flow => theme::muted(),
        DfdLineKind::Node | DfdLineKind::Summary => theme::subtle(),
    }
}

// ── FINDINGS pane ────────────────────────────────────────────────────────────

const FINDING_PROOF_LEGEND_MIN_HEIGHT: u16 = 10;
const FINDING_PREFIX_WIDTH: usize = 20;

pub(super) fn findings_pane_lines(model: &FindingsModel, inner: Rect) -> Vec<Line<'static>> {
    if model.rows.is_empty() {
        return empty_findings_pane_lines(model);
    }
    populated_findings_pane_lines(model, inner)
}

fn empty_findings_pane_lines(model: &FindingsModel) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(clean_scan) = &model.empty.clean_scan {
        lines.extend(clean_scan_empty_lines(clean_scan, &model.empty.ledger));
    } else {
        lines.extend(unscanned_empty_lines(&model.empty));
    }
    lines
}

fn clean_scan_empty_lines(clean_scan: &CleanScanEmptyState, ledger: &str) -> Vec<Line<'static>> {
    let details = [clean_scan.summary.as_str(), ledger];
    let ctas = [
        ("scan", "rerun scanners"),
        (
            "workspace export findings report.sarif",
            "export the clean report",
        ),
    ];
    pane_empty_state("0 findings", &details, &ctas)
}

fn unscanned_empty_lines(empty: &FindingsEmptyState) -> Vec<Line<'static>> {
    let mut ctas = vec![("scan", empty.hint)];
    if let Some(context_cta) = empty.context_cta {
        ctas.push(context_cta);
    }
    let details = [
        "the findings ledger is empty for this target.",
        empty.ledger.as_str(),
    ];
    pane_empty_state("no findings yet", &details, &ctas)
}

fn populated_findings_pane_lines(model: &FindingsModel, inner: Rect) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if should_show_proof_legend(inner.height) {
        lines.push(proof_legend_line());
    }
    if let Some(notice) = &model.selected_out_of_window {
        lines.push(Line::styled(
            fit(notice, inner.width as usize),
            theme::warn(),
        ));
    }
    let chrome_rows = lines.len();
    let visible = (inner.height as usize).saturating_sub(chrome_rows).max(1);
    let start = viewport_start_for_cursor(model.rows.len(), visible, model.cursor);
    let width = inner.width as usize;
    lines.extend(
        model
            .rows
            .iter()
            .skip(start)
            .take(visible)
            .map(|row| finding_row_line(row, width)),
    );
    lines
}

fn should_show_proof_legend(height: u16) -> bool {
    height >= FINDING_PROOF_LEGEND_MIN_HEIGHT
}

fn proof_legend_line() -> Line<'static> {
    Line::from(vec![
        Span::styled("proof ", theme::muted()),
        proof_legend_span("✓ runtime", ProofTier::RuntimeVerified),
        Span::styled(" · ", theme::subtle()),
        proof_legend_span("◇ reviewed/static", ProofTier::Confirmed),
        Span::styled(" · ", theme::subtle()),
        proof_legend_span("? guess", ProofTier::Suspected),
        Span::styled(" · ", theme::subtle()),
        proof_legend_span("! rejected", ProofTier::Rejected),
    ])
}

fn proof_legend_span(label: &'static str, tier: ProofTier) -> Span<'static> {
    Span::styled(label, proof_tier_style(tier))
}

fn finding_row_line(row: &FindingListRow, width: usize) -> Line<'static> {
    let (marker, marker_style) = row_marker(row);
    let mut spans = vec![
        Span::styled(marker.to_string(), marker_style),
        Span::styled(pad(&row.alias, 7), theme::accent()),
        Span::raw(" "),
        Span::styled(
            severity_glyph(row.severity_tone),
            theme::severity_tone(row.severity_tone),
        ),
        Span::raw(" "),
        Span::styled(pad(&proof_summary(row), 8), proof_label_style(row)),
        Span::raw(" "),
    ];
    spans.push(Span::styled(
        fit(&row.title, finding_title_budget(width)),
        theme::primary(),
    ));
    Line::from(spans)
}

fn finding_title_budget(width: usize) -> usize {
    width.saturating_sub(FINDING_PREFIX_WIDTH).max(8)
}

fn proof_label_style(row: &FindingListRow) -> ratatui::style::Style {
    proof_tier_style(row.proof_tier)
}

fn proof_tier_style(tier: ProofTier) -> ratatui::style::Style {
    match tier {
        ProofTier::RuntimeVerified => theme::success(),
        ProofTier::Confirmed => theme::label(),
        ProofTier::StaticLinked => theme::accent(),
        ProofTier::Suspected => theme::muted(),
        ProofTier::Rejected => theme::danger(),
    }
}

fn proof_summary(row: &FindingListRow) -> String {
    if row.confidence == "-" || row.verdict == "untriaged" {
        return row.proof_marker.to_string();
    }
    format!("{}{}{}", row.proof_marker, row.verdict, row.confidence)
}

fn severity_glyph(tone: SeverityTone) -> &'static str {
    match tone {
        SeverityTone::Critical => "C",
        SeverityTone::High => "H",
        SeverityTone::Medium => "M",
        SeverityTone::Low => "L",
        SeverityTone::Info => "I",
        SeverityTone::Unknown => "?",
    }
}

fn row_marker(row: &FindingListRow) -> (&'static str, ratatui::style::Style) {
    if row.cursor {
        ("▌ ", theme::accent())
    } else if row.selected {
        ("▌ ", theme::warn())
    } else {
        ("  ", theme::subtle())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_with_proof(
        proof_label: &str,
        proof_marker: &'static str,
        proof_tier: ProofTier,
    ) -> FindingListRow {
        FindingListRow {
            alias: "F-0001".to_string(),
            severity_tone: SeverityTone::High,
            severity_label: "HIGH".to_string(),
            title: "request reaches sink".to_string(),
            location: "crates/kuzushi-tui/src/app/example.rs:42".to_string(),
            run_label: "run:abc".to_string(),
            revision_label: "rev:def".to_string(),
            verdict: "tp".to_string(),
            confidence: "91%".to_string(),
            proof_label: proof_label.to_string(),
            proof_marker,
            proof_tier,
            cwe: "CWE-89".to_string(),
            source: "semgrep".to_string(),
            evidence: "source to sink".to_string(),
            selected: false,
            cursor: true,
        }
    }

    fn row_text(row: &FindingListRow, width: usize) -> String {
        finding_row_line(row, width)
            .spans
            .into_iter()
            .map(|span| span.content.into_owned())
            .collect::<String>()
    }

    fn line_text(line: Line<'static>) -> String {
        line.spans
            .into_iter()
            .map(|span| span.content.into_owned())
            .collect::<String>()
    }

    #[test]
    fn source_rows_fit_the_pane_width_without_wrapping() {
        let model = SourceTreeModel {
            rows: vec![
                SourceTreeRow {
                    depth: 3,
                    name: "applies_size_binary_and_severity_filters.rs".to_string(),
                    is_dir: false,
                    finding_count: 18,
                    component: None,
                },
                SourceTreeRow {
                    depth: 1,
                    name: "benchmark-regression.yml".to_string(),
                    is_dir: false,
                    finding_count: 1,
                    component: None,
                },
            ],
            file_count: 2,
            finding_count: 19,
            empty_hint: None,
        };

        for text in source_pane_lines(&model, 24).into_iter().map(line_text) {
            assert!(text.chars().count() <= 24, "{text}");
            assert!(text.contains('·'), "{text}");
        }
    }

    #[test]
    fn finding_row_prioritizes_title_over_provenance_when_width_allows() {
        let row = row_with_proof("path-linked", "◇", ProofTier::StaticLinked);
        let text = finding_row_line(&row, 80)
            .spans
            .into_iter()
            .map(|span| span.content.into_owned())
            .collect::<String>();

        assert!(text.contains("◇tp91%"), "{text}");
        assert!(text.contains("request reaches sink"), "{text}");
        assert!(!text.contains("example.rs:42"), "{text}");
        assert!(!text.contains("run:abc"), "{text}");
        assert!(!text.contains("rev:def"), "{text}");
    }

    #[test]
    fn finding_row_keeps_proof_marker_when_narrow() {
        let row = row_with_proof("unverified", "?", ProofTier::Suspected);
        let text = row_text(&row, 36);

        assert!(text.contains("H"), "{text}");
        assert!(text.contains("?"), "{text}");
        assert!(!text.contains("unverified"), "{text}");
        assert!(!text.contains("tp 91%"), "{text}");
    }

    #[test]
    fn finding_row_keeps_compact_proof_summary_before_title() {
        let row = row_with_proof("unverified", "?", ProofTier::Suspected);
        let text = row_text(&row, 52);

        assert!(text.contains(" ?"), "{text}");
        assert!(!text.contains("example.rs:42"), "{text}");
    }

    #[test]
    fn proof_legend_is_gated_until_findings_has_enough_rows() {
        assert!(!should_show_proof_legend(9));
        assert!(should_show_proof_legend(10));
    }
}
