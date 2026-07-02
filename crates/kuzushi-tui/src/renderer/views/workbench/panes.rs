//! Pure pane-body line builders for the Workbench command center. Shared by the
//! frame renderer (each list drawn inside a bordered `Block`) and the plain
//! `workbench_lines` path (each list stacked under a text divider).

use super::*;
use crate::ui_view_models::{
    threat_dfd_view, CodePaneModel, CodePaneRow, DfdLineKind, FindingListRow, FindingsModel,
    ProofTier, SeverityCounts, SeverityTone, SourceTreeModel, SourceTreeRow, WorkbenchCenter,
    WorkbenchCenterBody,
};
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Span};

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

pub(super) fn source_pane_lines(model: &SourceTreeModel) -> Vec<Line<'static>> {
    if let Some(hint) = model.empty_hint {
        return pane_empty_state(
            "no source tree",
            &[hint],
            &[("scan", "populate finding-bearing files")],
        );
    }
    model.rows.iter().map(source_row_line).collect()
}

fn source_row_line(row: &SourceTreeRow) -> Line<'static> {
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
    let mut spans = vec![Span::raw(indent), Span::styled(name, name_style)];
    if row.finding_count > 0 {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("· {}", row.finding_count),
            theme::muted(),
        ));
    }
    Line::from(spans)
}

// ── CENTER pane ──────────────────────────────────────────────────────────────

pub(super) fn center_pane_lines(
    app: &ShellApp,
    center: &WorkbenchCenter,
    width: usize,
) -> Vec<Line<'static>> {
    match &center.body {
        WorkbenchCenterBody::Code(code) => code_pane_lines(code, width),
        WorkbenchCenterBody::Dfd { empty_hint } => dfd_pane_lines(app, *empty_hint, width),
    }
}

fn dfd_pane_lines(
    app: &ShellApp,
    empty_hint: Option<&'static str>,
    width: usize,
) -> Vec<Line<'static>> {
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

const FINDING_PROOF_CHIP_WIDTH: usize = 44;
const FINDING_FULL_META_WIDTH: usize = 60;
const FINDING_RUN_META_WIDTH: usize = 96;

pub(super) fn findings_pane_lines(model: &FindingsModel, inner: Rect) -> Vec<Line<'static>> {
    if model.rows.is_empty() {
        let mut lines = vec![filter_chip_line(&model.counts, model.total)];
        let mut ctas = vec![("scan", model.empty.hint)];
        if let Some(context_cta) = model.empty.context_cta {
            ctas.push(context_cta);
        }
        let details = [
            "the findings ledger is empty for this target.",
            model.empty.ledger.as_str(),
        ];
        lines.extend(pane_empty_state("no findings yet", &details, &ctas));
        return lines;
    }
    let mut lines = vec![filter_chip_line(&model.counts, model.total)];
    lines.push(proof_legend_line());
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

fn filter_chip_line(counts: &SeverityCounts, total: usize) -> Line<'static> {
    let mut spans = vec![Span::styled(format!("all:{total}"), theme::accent())];
    for (label, count, tone) in [
        ("crit", counts.critical, SeverityTone::Critical),
        ("high", counts.high, SeverityTone::High),
        ("med", counts.medium, SeverityTone::Medium),
        ("low", counts.low, SeverityTone::Low),
    ] {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("{label}:{count}"),
            theme::severity_tone(tone),
        ));
    }
    Line::from(spans)
}

fn proof_legend_line() -> Line<'static> {
    Line::from(vec![
        Span::styled("proof ", theme::muted()),
        proof_legend_span("✓ runtime", ProofTier::Confirmed),
        Span::styled(" · ", theme::subtle()),
        proof_legend_span("◇ static/triaged", ProofTier::StaticLinked),
        Span::styled(" · ", theme::subtle()),
        proof_legend_span("? unconfirmed", ProofTier::Suspected),
        Span::styled(" · ", theme::subtle()),
        proof_legend_span("! rejected", ProofTier::Rejected),
        Span::styled("   conf verdict %", theme::muted()),
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
            severity_chip(row.severity_tone),
            theme::severity_tone(row.severity_tone),
        ),
        Span::raw(" "),
    ];
    if uses_inline_proof_marker(width) {
        spans.push(Span::styled(row.proof_marker, proof_label_style(row)));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        fit(&row.title, finding_title_budget(width)),
        theme::primary(),
    ));
    spans.extend(finding_row_meta_spans(row, width));
    Line::from(spans)
}

fn finding_title_budget(width: usize) -> usize {
    width
        .saturating_sub(finding_row_prefix_budget(width) + finding_row_meta_budget(width))
        .max(8)
}

fn finding_row_prefix_budget(width: usize) -> usize {
    16 + if uses_inline_proof_marker(width) {
        2
    } else {
        0
    }
}

fn uses_inline_proof_marker(width: usize) -> bool {
    width < FINDING_PROOF_CHIP_WIDTH
}

fn finding_row_meta_budget(width: usize) -> usize {
    if width < FINDING_PROOF_CHIP_WIDTH {
        return 0;
    }
    if width < FINDING_FULL_META_WIDTH {
        return 16;
    }
    let path_budget = finding_path_budget(width);
    27 + path_budget
        + if width >= FINDING_RUN_META_WIDTH {
            28
        } else {
            0
        }
}

fn finding_path_budget(width: usize) -> usize {
    if width >= FINDING_RUN_META_WIDTH {
        24
    } else {
        20
    }
}

fn finding_row_meta_spans(row: &FindingListRow, width: usize) -> Vec<Span<'static>> {
    if width < FINDING_PROOF_CHIP_WIDTH {
        return Vec::new();
    }
    if width < FINDING_FULL_META_WIDTH {
        return vec![
            Span::raw(" "),
            Span::styled(pad(&proof_chip(row), 15), proof_label_style(row)),
        ];
    }
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(pad(&finding_status_label(row), 9), theme::muted()),
        Span::raw(" "),
        Span::styled(pad(&proof_chip(row), 15), proof_label_style(row)),
        Span::raw(" "),
        Span::styled(
            fit_path(&row.location, finding_path_budget(width)),
            theme::subtle(),
        ),
    ];
    if width >= FINDING_RUN_META_WIDTH {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(pad(&row.run_label, 14), theme::muted()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(pad(&row.revision_label, 12), theme::subtle()));
    }
    spans
}

fn proof_label_style(row: &FindingListRow) -> ratatui::style::Style {
    proof_tier_style(row.proof_tier)
}

fn proof_tier_style(tier: ProofTier) -> ratatui::style::Style {
    match tier {
        ProofTier::Confirmed => theme::success(),
        ProofTier::StaticLinked => theme::accent(),
        ProofTier::Suspected => theme::warn(),
        ProofTier::Rejected => theme::danger(),
    }
}

fn proof_chip(row: &FindingListRow) -> String {
    format!("{} {}", row.proof_marker, row.proof_label)
}

fn finding_status_label(row: &FindingListRow) -> String {
    if row.confidence == "-" {
        row.verdict.clone()
    } else {
        format!("{} {}", row.verdict, row.confidence)
    }
}

fn severity_chip(tone: SeverityTone) -> String {
    pad(
        match tone {
            SeverityTone::Critical => "CRIT",
            SeverityTone::High => "HIGH",
            SeverityTone::Medium => "MED",
            SeverityTone::Low => "LOW",
            SeverityTone::Info => "INFO",
            SeverityTone::Unknown => "UNK",
        },
        5,
    )
}

fn row_marker(row: &FindingListRow) -> (&'static str, ratatui::style::Style) {
    if row.cursor {
        ("▌ ", theme::accent())
    } else if row.selected {
        ("* ", theme::warn())
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

    #[test]
    fn finding_row_includes_status_and_location_when_width_allows() {
        let row = row_with_proof("path-linked", "◇", ProofTier::StaticLinked);
        let text = finding_row_line(&row, 80)
            .spans
            .into_iter()
            .map(|span| span.content.into_owned())
            .collect::<String>();

        assert!(text.contains("tp 91%"), "{text}");
        assert!(text.contains("◇ path-linked"), "{text}");
        assert!(text.contains("example.rs:42"), "{text}");
    }

    #[test]
    fn finding_row_keeps_proof_marker_when_narrow() {
        let row = row_with_proof("unverified", "?", ProofTier::Suspected);
        let text = row_text(&row, 36);

        assert!(text.contains("HIGH"), "{text}");
        assert!(text.contains("?"), "{text}");
        assert!(!text.contains("unverified"), "{text}");
        assert!(!text.contains("tp 91%"), "{text}");
    }

    #[test]
    fn finding_row_shows_proof_chip_before_full_meta_fits() {
        let row = row_with_proof("unverified", "?", ProofTier::Suspected);
        let text = row_text(&row, 52);

        assert!(text.contains("? unverified"), "{text}");
        assert!(!text.contains("example.rs:42"), "{text}");
    }
}
