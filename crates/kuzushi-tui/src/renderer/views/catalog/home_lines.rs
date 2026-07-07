use super::*;
use crate::ui_view_models::{
    home_cockpit_model, AttackSurfaceRiskModel, HomeCockpitModel, HomeFindingsCard, HomeNextCard,
    HomeRunArtifactChip, HomeRunCard, HomeTopRiskRow, JourneyModel, SeverityCounts, SeverityTone,
};
use ratatui::style::Style;

pub(crate) fn home_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = home_cockpit_model(app);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(model.title, area.width));
    lines.push(blank());
    if let Some(journey) = &model.journey {
        append_journey_rail(&mut lines, journey);
        lines.push(blank());
    }
    append_next_card(&mut lines, &model.next_card, area.width as usize);
    lines.push(blank());
    append_findings_card(&mut lines, &model, area.width as usize);
    append_top_risks(&mut lines, &model.top_risks, area.width as usize);
    lines.push(blank());
    append_run_card(&mut lines, &model.run_card, area.width as usize);
    lines.push(blank());
    lines.push(workspace_line(&model.workspace_line, area.width as usize));
    lines.push(blank());
    lines.push(command_list_line(
        &model.command_labels,
        area.width as usize,
    ));
    lines
}

fn append_journey_rail(lines: &mut Vec<Line<'static>>, journey: &JourneyModel) {
    lines.push(journey_phase_labels_line(journey));
    lines.push(journey_phase_states_line(journey));
}

fn journey_phase_labels_line(journey: &JourneyModel) -> Line<'static> {
    let mut spans = vec![Span::raw("  ")];
    for (index, status) in journey.phases.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" ──── ", theme::subtle()));
        }
        spans.push(Span::styled(
            status.phase_label.trim().to_string(),
            journey_phase_tone_style(status.tone),
        ));
    }
    Line::from(spans)
}

fn journey_phase_states_line(journey: &JourneyModel) -> Line<'static> {
    let mut spans = vec![Span::raw("  ")];
    for (index, status) in journey.phases.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("       "));
        }
        spans.push(Span::styled(
            pad(&journey_state_label(status), journey_state_width(index)),
            journey_phase_tone_style(status.tone),
        ));
    }
    Line::from(spans)
}

fn journey_state_label(status: &crate::ui_view_models::JourneyPhaseStatus) -> String {
    if status.state == crate::ui_view_models::JourneyPhaseState::Current {
        return format!("{} {} of 4", status.state_symbol, status.phase.position());
    }
    status.state_symbol.to_string()
}

fn journey_state_width(index: usize) -> usize {
    [6, 7, 10, 6].get(index).copied().unwrap_or(6)
}

fn append_next_card(lines: &mut Vec<Line<'static>>, card: &HomeNextCard, width: usize) {
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("▸ NEXT   ", theme::warn()),
        Span::styled(
            fit(&card.action, width.saturating_sub(11)),
            theme::primary(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("           "),
        Span::styled(
            fit(&card.mechanics, width.saturating_sub(11)),
            theme::muted(),
        ),
    ]));
}

fn append_findings_card(lines: &mut Vec<Line<'static>>, model: &HomeCockpitModel, width: usize) {
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("FINDINGS   ", theme::label()),
        Span::styled(model.findings_card.total.to_string(), theme::primary()),
    ]));
    lines.push(severity_bar_line(&model.findings_card, width));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(findings_counts_label(&model.findings_card), theme::muted()),
    ]));
    if let Some(surface) = &model.attack_surface {
        lines.push(surface_risk_line(surface, width));
    }
}

fn severity_bar_line(card: &HomeFindingsCard, width: usize) -> Line<'static> {
    if card.total == 0 {
        return Line::from(vec![
            Span::raw("  "),
            Span::styled("no findings loaded", theme::muted()),
        ]);
    }
    let mut spans = vec![Span::raw("  ")];
    for segment in severity_bar_segments(card, severity_bar_width(width)) {
        spans.push(Span::styled(segment.text, segment.style));
    }
    Line::from(spans)
}

fn severity_bar_width(width: usize) -> usize {
    width.saturating_sub(4).min(64).max(8)
}

struct BarSegment {
    text: String,
    style: Style,
}

fn severity_bar_segments(card: &HomeFindingsCard, width: usize) -> Vec<BarSegment> {
    let mut segments = Vec::new();
    let mut cursor = 0usize;
    for (tone, count) in reviewed_severity_units(card) {
        let next = cursor + count;
        push_bar_segment(
            &mut segments,
            cursor,
            next,
            card.total,
            width,
            severity_style(tone),
        );
        cursor = next;
    }
    push_bar_segment(
        &mut segments,
        card.reviewed,
        card.total,
        card.total,
        width,
        theme::subtle(),
    );
    segments
}

fn reviewed_severity_units(card: &HomeFindingsCard) -> Vec<(SeverityTone, usize)> {
    let counts = card.reviewed_counts;
    let known = known_severity_total(counts);
    vec![
        (SeverityTone::Critical, counts.critical),
        (SeverityTone::High, counts.high),
        (SeverityTone::Medium, counts.medium),
        (SeverityTone::Low, counts.low),
        (SeverityTone::Info, counts.info),
        (SeverityTone::Unknown, card.reviewed.saturating_sub(known)),
    ]
}

fn push_bar_segment(
    segments: &mut Vec<BarSegment>,
    start: usize,
    end: usize,
    total: usize,
    width: usize,
    style: Style,
) {
    let blocks = scaled_segment_blocks(start, end, total, width);
    if blocks > 0 {
        segments.push(BarSegment {
            text: bar_block(style, blocks),
            style,
        });
    }
}

fn scaled_segment_blocks(start: usize, end: usize, total: usize, width: usize) -> usize {
    let left = start.saturating_mul(width) / total.max(1);
    let right = end.saturating_mul(width) / total.max(1);
    right.saturating_sub(left)
}

fn bar_block(style: Style, blocks: usize) -> String {
    if style == theme::subtle() {
        return "▒".repeat(blocks);
    }
    "▇".repeat(blocks)
}

fn findings_counts_label(card: &HomeFindingsCard) -> String {
    if card.total == 0 {
        return "0 findings".to_string();
    }
    let mut parts = severity_count_parts(card.counts, card.total);
    parts.push(format!(
        "{} unreviewed / {} reviewed",
        card.unreviewed, card.reviewed
    ));
    parts.join(" · ")
}

fn severity_count_parts(counts: SeverityCounts, total: usize) -> Vec<String> {
    let mut parts = Vec::new();
    push_count_part(&mut parts, counts.critical, "critical");
    push_count_part(&mut parts, counts.high, "high");
    push_count_part(&mut parts, counts.medium, "medium");
    push_count_part(&mut parts, counts.low, "low");
    push_count_part(&mut parts, counts.info, "info");
    push_count_part(
        &mut parts,
        total.saturating_sub(known_severity_total(counts)),
        "unknown",
    );
    parts
}

fn push_count_part(parts: &mut Vec<String>, count: usize, label: &str) {
    if count > 0 {
        parts.push(format!("{count} {label}"));
    }
}

fn known_severity_total(counts: SeverityCounts) -> usize {
    counts.critical + counts.high + counts.medium + counts.low + counts.info
}

fn severity_style(tone: SeverityTone) -> Style {
    theme::severity_tone(tone)
}

fn surface_risk_line(surface: &AttackSurfaceRiskModel, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled("SURFACE    ", theme::label()),
        Span::styled(
            fit(&surface.summary, width.saturating_sub(13)),
            theme::muted(),
        ),
    ])
}

fn append_top_risks(lines: &mut Vec<Line<'static>>, rows: &[HomeTopRiskRow], width: usize) {
    if rows.is_empty() {
        return;
    }
    lines.push(blank());
    lines.push(top_risks_header(width));
    lines.extend(rows.iter().map(|row| top_risk_line(row, width)));
}

fn top_risks_header(width: usize) -> Line<'static> {
    let suffix = "`findings` to review";
    let pad_width = width.saturating_sub(12 + suffix.chars().count()).max(2);
    Line::from(vec![
        Span::raw("  "),
        Span::styled("TOP RISKS", theme::label()),
        Span::raw(" ".repeat(pad_width)),
        Span::styled(suffix, theme::muted()),
    ])
}

fn top_risk_line(row: &HomeTopRiskRow, width: usize) -> Line<'static> {
    let rule_width = top_risk_rule_width(width);
    let location_width = width.saturating_sub(18 + rule_width).max(8);
    Line::from(vec![
        Span::raw("  "),
        Span::styled(
            severity_glyph(row.severity_tone),
            severity_style(row.severity_tone),
        ),
        Span::raw("  "),
        Span::styled(pad(&row.alias, 7), theme::accent()),
        Span::raw(" "),
        Span::styled(pad(&row.rule, rule_width), theme::primary()),
        Span::styled(fit(&row.location, location_width), theme::muted()),
    ])
}

fn top_risk_rule_width(width: usize) -> usize {
    width.saturating_div(4).clamp(14, 28)
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

fn append_run_card(lines: &mut Vec<Line<'static>>, card: &HomeRunCard, width: usize) {
    lines.push(run_header_line(card, width));
    append_run_artifact_chips(lines, &card.artifacts, width);
    lines.push(run_dir_line(card, width));
}

fn run_header_line(card: &HomeRunCard, width: usize) -> Line<'static> {
    let run_id_width = width.saturating_sub(46).max(8);
    Line::from(vec![
        Span::raw("  "),
        Span::styled("RUN   ", theme::label()),
        Span::styled(fit(&card.run_id, run_id_width), theme::accent()),
        Span::styled(" · ", theme::subtle()),
        Span::styled(card.status.clone(), run_status_style(&card.status)),
        Span::styled(" · ", theme::subtle()),
        Span::styled(
            format!("artifacts {}/{} recorded", card.recorded, card.total),
            theme::muted(),
        ),
    ])
}

fn run_status_style(status: &str) -> Style {
    match status {
        "completed" => theme::success(),
        "failed" => theme::danger(),
        "no runs yet" => theme::muted(),
        _ => theme::primary(),
    }
}

fn append_run_artifact_chips(
    lines: &mut Vec<Line<'static>>,
    artifacts: &[HomeRunArtifactChip],
    width: usize,
) {
    let mut row = ArtifactChipRow::new(width);
    for chip in artifacts {
        if let Some(line) = row.push(chip) {
            lines.push(line);
        }
    }
    lines.push(row.finish());
}

struct ArtifactChipRow {
    width: usize,
    used: usize,
    spans: Vec<Span<'static>>,
}

impl ArtifactChipRow {
    fn new(width: usize) -> Self {
        Self {
            width,
            used: 8,
            spans: vec![Span::raw("        ")],
        }
    }

    fn push(&mut self, chip: &HomeRunArtifactChip) -> Option<Line<'static>> {
        let width = chip_width(chip);
        if self.used > 8 && self.used + width + 2 > self.width {
            let line = self.take_line();
            self.push_chip(chip, width);
            return Some(line);
        }
        if self.used > 8 {
            self.push_separator();
        }
        self.push_chip(chip, width);
        None
    }

    fn push_separator(&mut self) {
        self.spans.push(Span::raw("  "));
        self.used += 2;
    }

    fn push_chip(&mut self, chip: &HomeRunArtifactChip, width: usize) {
        self.spans
            .push(Span::styled(chip.label.clone(), theme::muted()));
        self.spans.push(Span::raw(" "));
        self.spans
            .push(Span::styled(chip.glyph.clone(), chip_style(chip)));
        self.used += width;
    }

    fn take_line(&mut self) -> Line<'static> {
        let spans = std::mem::replace(&mut self.spans, vec![Span::raw("        ")]);
        self.used = 8;
        Line::from(spans)
    }

    fn finish(self) -> Line<'static> {
        Line::from(self.spans)
    }
}

fn chip_width(chip: &HomeRunArtifactChip) -> usize {
    chip.label.chars().count() + 1 + chip.glyph.chars().count()
}

fn chip_style(chip: &HomeRunArtifactChip) -> Style {
    match chip.state.as_str() {
        "recorded" => theme::success(),
        "partial" => theme::warn(),
        "failed" | "malformed" | "not a file" => theme::danger(),
        "missing" => theme::subtle(),
        _ => theme::muted(),
    }
}

fn run_dir_line(card: &HomeRunCard, width: usize) -> Line<'static> {
    let text = format!("{} · `show runs` for detail", card.run_dir);
    Line::from(vec![
        Span::raw("        "),
        Span::styled(fit(&text, width.saturating_sub(8)), theme::muted()),
    ])
}

fn workspace_line(value: &str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled("WORKSPACE   ", theme::label()),
        Span::styled(fit(value, width.saturating_sub(14)), theme::muted()),
    ])
}
