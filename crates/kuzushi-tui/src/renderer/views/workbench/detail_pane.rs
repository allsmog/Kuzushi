//! Finding detail line builder for the Workbench DETAILS pane.

use super::*;
use crate::ui_view_models::{
    FindingDetailModel, FindingEvidenceRow, ProofTier, TriageSummaryModel,
};
use ratatui::prelude::{Line, Span};
use ratatui::style::Style;

pub(super) fn detail_pane_lines(
    detail: &Option<FindingDetailModel>,
    width: usize,
    report_command: Option<&'static str>,
) -> Vec<Line<'static>> {
    let Some(detail) = detail else {
        return no_detail_lines();
    };
    let budget = width.saturating_sub(2).max(16);
    detail_lines_for_model(detail, budget, report_command)
}

fn no_detail_lines() -> Vec<Line<'static>> {
    vec![muted(
        "no finding selected — move through FINDINGS to preview details here.",
    )]
}

fn detail_lines_for_model(
    detail: &FindingDetailModel,
    budget: usize,
    report_command: Option<&'static str>,
) -> Vec<Line<'static>> {
    let mut lines = detail_title_lines(detail, budget);
    lines.push(blank_line());
    push_status_section(&mut lines, detail, budget);
    push_next_section(&mut lines, detail, budget, report_command);
    push_fix_section(&mut lines, detail, budget);
    push_triage_section(&mut lines, &detail.triage, budget);
    push_evidence_section(
        &mut lines,
        &detail.evidence,
        detail.evidence_overflow,
        budget,
    );
    push_message_section(&mut lines, detail, budget);
    push_reference_footer(&mut lines, detail, budget);
    lines
}

fn push_status_section(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, budget: usize) {
    lines.push(section_line("STATUS"));
    push_wrapped(
        lines,
        &format!(
            "confirmation: {} {}",
            detail.proof_marker, detail.proof_label
        ),
        budget,
        "  ",
        proof_detail_style(detail.proof_tier),
    );
    push_wrapped(
        lines,
        &format!(
            "static: {} - {}",
            detail.static_proof_label, detail.static_proof_explanation
        ),
        budget,
        "  ",
        theme::label(),
    );
    push_wrapped(
        lines,
        &format!(
            "runtime: {} - {}",
            detail.runtime_label, detail.runtime_explanation
        ),
        budget,
        "  ",
        theme::muted(),
    );
}

fn proof_detail_style(tier: ProofTier) -> Style {
    match tier {
        ProofTier::RuntimeVerified => theme::success(),
        ProofTier::Confirmed => theme::label(),
        ProofTier::StaticLinked => theme::accent(),
        ProofTier::Suspected => theme::muted(),
        ProofTier::Rejected => theme::danger(),
    }
}

fn push_next_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
    report_command: Option<&'static str>,
) {
    lines.push(section_line("NEXT"));
    match &detail.next_command {
        Some(command) => push_wrapped(
            lines,
            &format!("{}: `{command}`", detail.next_action_label),
            budget,
            "  ",
            theme::accent(),
        ),
        None => push_wrapped(
            lines,
            &format!("{}: {}", detail.next_action_label, detail.next_detail),
            budget,
            "  ",
            theme::accent(),
        ),
    }
    if detail.next_command.is_some() {
        push_wrapped(lines, &detail.next_detail, budget, "  ", theme::muted());
    }
    if let Some(report_command) = report_command {
        push_wrapped(
            lines,
            &format!("report: `{report_command}`"),
            budget,
            "  ",
            theme::muted(),
        );
    }
}

fn push_fix_section(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, budget: usize) {
    let Some(hint) = detail.remediation_hint.as_deref() else {
        return;
    };
    lines.push(section_line("FIX"));
    push_wrapped(lines, hint, budget, "  ", theme::primary());
}

fn push_message_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    lines.push(section_line("SCANNER MESSAGE"));
    if detail.message_lines.is_empty() {
        lines.push(muted("  no message recorded"));
        return;
    }
    for message in &detail.message_lines {
        push_wrapped(lines, message, budget, "  ", theme::primary());
    }
    push_overflow_notice(lines, detail.message_overflow, "message line");
}

fn push_triage_section(
    lines: &mut Vec<Line<'static>>,
    triage: &Option<TriageSummaryModel>,
    budget: usize,
) {
    let Some(triage) = triage else {
        return;
    };
    lines.push(section_line("TRIAGE"));
    push_wrapped(
        lines,
        &format!(
            "{} · confidence {} · by {}",
            triage.verdict, triage.confidence, triage.author
        ),
        budget,
        "  ",
        theme::label(),
    );
    push_wrapped(lines, &triage.rationale, budget, "  ", theme::muted());
}

fn push_evidence_section(
    lines: &mut Vec<Line<'static>>,
    evidence: &[FindingEvidenceRow],
    overflow: usize,
    budget: usize,
) {
    lines.push(section_line("EVIDENCE"));
    if evidence.is_empty() {
        lines.push(muted("  no evidence rows recorded"));
        return;
    }
    for (index, row) in evidence.iter().enumerate() {
        push_evidence_row(lines, row, budget, index > 0);
    }
    push_overflow_notice(lines, overflow, "evidence row");
}

fn push_overflow_notice(lines: &mut Vec<Line<'static>>, hidden: usize, noun: &'static str) {
    if hidden == 0 {
        return;
    }
    let plural = if hidden == 1 { "" } else { "s" };
    lines.push(Line::styled(
        format!("  … {hidden} more {noun}{plural}"),
        theme::muted(),
    ));
}

fn push_evidence_row(
    lines: &mut Vec<Line<'static>>,
    evidence: &FindingEvidenceRow,
    budget: usize,
    separated: bool,
) {
    if separated {
        lines.push(blank_line());
    }
    push_wrapped(lines, &evidence.header, budget, "  ", theme::label());
    push_optional_wrapped(lines, &evidence.snippet, budget, "    ", theme::primary());
    push_optional_wrapped(lines, &evidence.rationale, budget, "    ", theme::muted());
    if let Some(capture) = &evidence.capture {
        push_optional_wrapped(lines, capture, budget, "    ", theme::muted());
    }
}

fn push_reference_footer(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    lines.push(blank_line());
    push_detail_kv(lines, "location", &detail.location, budget);
    push_detail_kv(lines, "rule", &detail.rule, budget);
    push_detail_kv(lines, "tool", &detail.tool, budget);
    push_detail_kv(lines, "source signature", &detail.source_signature, budget);
    push_detail_kv(lines, "corroboration", &detail.corroboration, budget);
    push_detail_kv(lines, "fingerprint", &detail.fingerprint, budget);
    push_alias_note(lines, budget);
}

fn push_alias_note(lines: &mut Vec<Line<'static>>, budget: usize) {
    push_wrapped(
        lines,
        "ids like F-0001 are aliases · show aliases to list",
        budget,
        "",
        theme::muted(),
    );
}

fn detail_title_lines(detail: &FindingDetailModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    push_wrapped(&mut lines, &detail.title, width, "", theme::heading());
    lines
}

fn push_detail_kv(lines: &mut Vec<Line<'static>>, key: &'static str, value: &str, width: usize) {
    if value.trim().is_empty() || value == "-" {
        return;
    }
    push_wrapped(lines, &format!("{key}: {value}"), width, "", theme::muted());
}

fn section_line(label: &'static str) -> Line<'static> {
    Line::from(Span::styled(label, theme::accent()))
}

fn blank_line() -> Line<'static> {
    Line::raw(String::new())
}

fn push_wrapped(
    lines: &mut Vec<Line<'static>>,
    value: &str,
    width: usize,
    prefix: &'static str,
    style: Style,
) {
    let budget = width.saturating_sub(prefix.chars().count()).max(8);
    for chunk in crate::renderer::shared::text::wrap_text(value, budget) {
        lines.push(Line::from(vec![
            Span::raw(prefix.to_string()),
            Span::styled(chunk, style),
        ]));
    }
}

fn push_optional_wrapped(
    lines: &mut Vec<Line<'static>>,
    value: &str,
    width: usize,
    prefix: &'static str,
    style: Style,
) {
    if value.trim().is_empty() {
        return;
    }
    push_wrapped(lines, value, width, prefix, style);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{ProofTier, SeverityTone, WORKBENCH_REPORT_COMMAND};

    fn detail() -> FindingDetailModel {
        FindingDetailModel {
            alias: Some("F-0001".to_string()),
            severity_tone: SeverityTone::High,
            severity_label: "high".to_string(),
            title: "demo finding".to_string(),
            location: "src/app.rs:42".to_string(),
            rule: "demo.rule".to_string(),
            tool: "demo".to_string(),
            source_signature: "app.rs:42:demo-finding".to_string(),
            corroboration: "1".to_string(),
            fingerprint: "fp-demo".to_string(),
            proof_label: "unverified".to_string(),
            proof_marker: "?",
            proof_tier: ProofTier::Suspected,
            proof_state: "not recorded".to_string(),
            runtime_verification: "not run".to_string(),
            static_proof_label: "not recorded".to_string(),
            static_proof_explanation: "no static proof recorded".to_string(),
            runtime_label: "not verified".to_string(),
            runtime_explanation: "runtime verification has not run".to_string(),
            next_action_label: "validate".to_string(),
            next_command: Some("verify F-0001".to_string()),
            next_detail: "collect runtime proof or stronger source evidence before patching"
                .to_string(),
            remediation_hint: None,
            evidence: vec![FindingEvidenceRow {
                header: "source · conf 90 · src/app.rs:42".to_string(),
                snippet: "request reaches sink".to_string(),
                rationale: "tainted input".to_string(),
                capture: Some("http capture: request body recorded".to_string()),
            }],
            message_lines: vec!["line 1".to_string()],
            message_overflow: 2,
            evidence_overflow: 3,
            triage: None,
        }
    }

    fn detail_text(report_command: Option<&'static str>) -> String {
        detail_lines_for_model(&detail(), 80, report_command)
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.into_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn detail_lines_disclose_hidden_message_and_evidence_rows() {
        let text = detail_text(None);

        assert!(text.contains("STATUS"), "{text}");
        assert!(text.contains("confirmation: ? unverified"), "{text}");
        assert!(text.contains("static: not recorded"), "{text}");
        assert!(text.contains("NEXT"), "{text}");
        assert!(text.contains("validate: `verify F-0001`"), "{text}");
        assert!(
            text.contains("http capture: request body recorded"),
            "{text}"
        );
        assert!(text.contains("… 2 more message lines"), "{text}");
        assert!(text.contains("… 3 more evidence rows"), "{text}");
    }

    #[test]
    fn detail_actions_include_report_command_when_available() {
        let text = detail_text(Some(WORKBENCH_REPORT_COMMAND));

        assert!(text.contains("`workspace export findings"), "{text}");
        assert!(text.contains("report.sarif`"), "{text}");
        assert!(text.contains("validate: `verify F-0001`"), "{text}");
        assert!(text.contains("report:"), "{text}");
        assert!(!text.contains("o open in editor"), "{text}");
        assert!(!text.contains("proof:"), "{text}");
        assert!(!text.contains("actions:"), "{text}");
    }
}
