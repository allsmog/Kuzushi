//! Finding detail line builder for the Workbench DETAILS pane.

use super::*;
use crate::ui_view_models::{FindingDetailModel, FindingEvidenceRow, ProofTier};
use kuzushi_core::findings::DataflowEvidenceRow;
use ratatui::prelude::{Line, Span};
use ratatui::style::Style;

pub(super) fn detail_pane_lines(
    detail: &Option<FindingDetailModel>,
    width: usize,
    report_command: Option<&str>,
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
    report_command: Option<&str>,
) -> Vec<Line<'static>> {
    let mut lines = detail_title_lines(detail, budget);
    push_signals_section(&mut lines, detail, budget);
    push_decision_section(&mut lines, detail, budget);
    push_next_section(&mut lines, detail, budget, report_command);
    push_source_section(&mut lines, detail, budget);
    push_evidence_section(
        &mut lines,
        &detail.evidence,
        detail.evidence_overflow,
        budget,
    );
    push_dataflow_section(
        &mut lines,
        &detail.dataflow_evidence,
        detail.dataflow_overflow,
        budget,
    );
    push_verification_section(&mut lines, detail, budget);
    push_analysis_section(&mut lines, detail, budget);
    push_claim_section(&mut lines, detail, budget);
    push_fix_section(&mut lines, detail, budget);
    push_message_section(&mut lines, detail, budget);
    push_provenance_section(&mut lines, detail, budget);
    lines
}

fn push_claim_section(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, budget: usize) {
    push_section_header(lines, "CLAIM");
    if let Some(alias) = detail.alias.as_deref() {
        push_detail_kv(lines, "alias", alias, budget);
    }
    push_detail_kv(lines, "rule", &detail.rule, budget);
    push_detail_kv(lines, "location", &detail.location, budget);
    push_detail_kv(lines, "producing tool", &detail.tool, budget);
}

fn push_signals_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    push_section_header(lines, "STATUS");
    push_detail_kv(lines, "severity", &detail.severity_label, budget);
    push_wrapped(
        lines,
        &format!("confidence: {}", detail.proof_confidence_label),
        budget,
        "  ",
        theme::proof_confidence_tone(detail.proof_confidence),
    );
    push_detail_kv(lines, "lifecycle status", &detail.lifecycle_status, budget);
    push_detail_kv(lines, "evidence state", &detail.evidence_state, budget);
    push_wrapped(
        lines,
        &format!(
            "proof summary: {} {}",
            detail.proof_marker, detail.proof_label
        ),
        budget,
        "  ",
        proof_detail_style(detail.proof_tier),
    );
}

fn proof_detail_style(tier: ProofTier) -> Style {
    match tier {
        ProofTier::RuntimeVerified => theme::success(),
        ProofTier::StaticLinked => theme::accent(),
        ProofTier::Suspected => theme::muted(),
        ProofTier::Rejected => theme::danger(),
    }
}

fn push_next_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
    report_command: Option<&str>,
) {
    push_section_header(lines, "NEXT");
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

fn push_source_section(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, budget: usize) {
    let Some(snippet) = detail.source_snippet.as_ref() else {
        return;
    };
    push_section_header(lines, "SOURCE · observation (on-disk excerpt)");
    push_wrapped(lines, &detail.location, budget, "  ", theme::muted());
    if let Some(note) = snippet.note.as_deref() {
        push_wrapped(lines, note, budget, "  ", theme::warn());
    }
    let number_width = snippet_number_width(snippet);
    for (offset, text) in snippet.lines.iter().enumerate() {
        lines.push(snippet_code_line(
            snippet,
            offset,
            text,
            number_width,
            budget,
        ));
    }
}

fn snippet_number_width(snippet: &crate::ui_view_models::SourceSnippetModel) -> usize {
    let last = snippet.start_line + snippet.lines.len().saturating_sub(1);
    last.to_string().chars().count()
}

/// One gutter-numbered code row. Code is clipped, never wrapped — a wrapped
/// source line reads as two source lines. The finding's own line carries the
/// marker and the brighter style so the eye lands on it first.
fn snippet_code_line(
    snippet: &crate::ui_view_models::SourceSnippetModel,
    offset: usize,
    text: &str,
    number_width: usize,
    budget: usize,
) -> Line<'static> {
    let number = snippet.start_line + offset;
    let focused = number == snippet.focus_line;
    let marker = if focused { "▶" } else { " " };
    let gutter = format!("  {marker} {number:>number_width$} │ ");
    let code_budget = budget
        .saturating_sub(crate::renderer::shared::text::display_width(&gutter))
        .max(8);
    let (gutter_style, code_style) = if focused {
        (theme::accent(), theme::primary())
    } else {
        (theme::subtle(), theme::muted())
    };
    Line::from(vec![
        Span::styled(gutter, gutter_style),
        Span::styled(fit(text, code_budget), code_style),
    ])
}

fn push_fix_section(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, budget: usize) {
    let Some(hint) = detail.remediation_hint.as_deref() else {
        return;
    };
    push_section_header(lines, "FIX");
    push_wrapped(lines, hint, budget, "  ", theme::primary());
}

fn push_message_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    push_section_header(lines, "SCANNER MESSAGE");
    if detail.message_lines.is_empty() {
        lines.push(muted("  no message recorded"));
        return;
    }
    for message in &detail.message_lines {
        push_wrapped(lines, message, budget, "  ", theme::primary());
    }
    push_overflow_notice(lines, detail.message_overflow, "message line");
}

fn push_analysis_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    push_section_header(lines, "ANALYSIS");
    push_wrapped(
        lines,
        &format!(
            "static proof: {} - {}",
            detail.static_proof_label, detail.static_proof_explanation
        ),
        budget,
        "  ",
        theme::label(),
    );
}

fn push_verification_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    push_section_header(lines, "VERIFICATION");
    push_wrapped(
        lines,
        &format!(
            "runtime verification: {} - {}",
            detail.runtime_label, detail.runtime_explanation
        ),
        budget,
        "  ",
        theme::muted(),
    );
}

fn push_decision_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    push_section_header(lines, "DECISION");
    push_decision_summary_lines(lines, detail, budget);
    push_triage_decision_lines(lines, detail, budget);
    push_review_action_lines(lines, budget);
}

fn push_review_action_lines(lines: &mut Vec<Line<'static>>, budget: usize) {
    for action in [
        "decide: `decision <true-positive|false-positive> <reason>`",
        "dismiss: `dismiss <reason> <note>`",
        "suppress: `suppress <id> --reason <text> --days 90`",
    ] {
        push_wrapped(lines, action, budget, "  ", theme::muted());
    }
}

fn push_decision_summary_lines(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    push_wrapped(
        lines,
        &format!("current decision: {}", detail.decision),
        budget,
        "  ",
        theme::label(),
    );
    push_wrapped(
        lines,
        &format!("decision source: {}", detail.decision_source),
        budget,
        "  ",
        theme::muted(),
    );
    push_wrapped(
        lines,
        &format!("decision history: {}", detail.decision_history),
        budget,
        "  ",
        theme::muted(),
    );
    if let Some(conflict) = detail.decision_conflict.as_deref() {
        push_wrapped(
            lines,
            &format!("decision conflict: {conflict}"),
            budget,
            "  ",
            theme::warn(),
        );
    }
}

fn push_triage_decision_lines(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    let Some(triage) = &detail.triage else {
        return;
    };
    push_wrapped(
        lines,
        &format!(
            "review decision: {} · confidence {} · by {} · source {}",
            triage.review_decision, triage.confidence, triage.author, triage.source
        ),
        budget,
        "  ",
        theme::label(),
    );
    push_wrapped(
        lines,
        &format!("legacy triage verdict: {}", triage.verdict),
        budget,
        "  ",
        theme::muted(),
    );
    push_wrapped(
        lines,
        &format!(
            "{}: {}",
            triage_rationale_label(&triage.author),
            triage.rationale
        ),
        budget,
        "  ",
        theme::muted(),
    );
}

fn triage_rationale_label(author: &str) -> &'static str {
    match author {
        "auto" => "automated/model-generated review reasoning",
        "human" => "human review rationale",
        "imported" => "imported review rationale",
        _ => "review rationale",
    }
}

fn push_evidence_section(
    lines: &mut Vec<Line<'static>>,
    evidence: &[FindingEvidenceRow],
    overflow: usize,
    budget: usize,
) {
    push_section_header(lines, "EVIDENCE");
    if evidence.is_empty() {
        lines.push(muted("  no evidence rows recorded"));
        return;
    }
    for (index, row) in evidence.iter().enumerate() {
        push_evidence_row(lines, row, budget, index > 0);
    }
    push_overflow_notice(lines, overflow, "evidence row");
}

/// The deep-auditor's cited dataflow (source/sink/guard/context) rendered
/// with the same evidence-row layout. Empty rows render nothing — no header —
/// so a finding the auditor never inspected shows no phantom section.
fn push_dataflow_section(
    lines: &mut Vec<Line<'static>>,
    dataflow: &[DataflowEvidenceRow],
    overflow: usize,
    budget: usize,
) {
    if dataflow.is_empty() {
        return;
    }
    push_section_header(lines, "AUDITED DATAFLOW");
    for (index, row) in dataflow.iter().enumerate() {
        push_evidence_row(
            lines,
            &FindingEvidenceRow::from_dataflow(row),
            budget,
            index > 0,
        );
    }
    push_overflow_notice(lines, overflow, "dataflow row");
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
    push_wrapped(
        lines,
        &format!("origin: {}", evidence.origin),
        budget,
        "  ",
        theme::muted(),
    );
    push_wrapped(lines, &evidence.header, budget, "  ", theme::label());
    push_optional_summary_line(lines, &evidence.snippet, budget, "    ", theme::primary());
    push_optional_summary_line(lines, &evidence.rationale, budget, "    ", theme::muted());
    if let Some(capture) = &evidence.capture {
        push_optional_summary_line(lines, capture, budget, "    ", theme::muted());
    }
}

fn push_provenance_section(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    push_section_header(lines, "PROVENANCE");
    push_detail_kv(lines, "run", &detail.run_label, budget);
    push_detail_kv(lines, "run status", &detail.run_status, budget);
    push_detail_kv(lines, "run tool", &detail.run_tool, budget);
    push_detail_kv(lines, "run model", &detail.run_model, budget);
    push_detail_kv(lines, "run runtime", &detail.run_runtime, budget);
    push_detail_kv(
        lines,
        "kuzushi version",
        &detail.run_kuzushi_version,
        budget,
    );
    push_detail_kv(lines, "revision", &detail.revision_label, budget);
    push_detail_kv(lines, "branch", &detail.branch_label, budget);
    push_detail_kv(lines, "vuln source", &detail.vuln_source_label, budget);
    push_detail_kv(lines, "source signature", &detail.source_signature, budget);
    push_detail_kv(lines, "corroboration", &detail.corroboration, budget);
    push_detail_kv(lines, "identity", &detail.identity_label, budget);
    push_detail_kv(
        lines,
        "fingerprint",
        &compact_fingerprint(&detail.fingerprint),
        budget,
    );
    if detail.alias.is_none() {
        push_alias_note(lines, budget);
    }
}

/// A full `fp3_<64 hex>` value wraps into unreadable hex soup. The first 20
/// characters are an unambiguous, typable prefix (reference resolution
/// accepts prefixes), so clip honestly with an ellipsis.
fn compact_fingerprint(fingerprint: &str) -> String {
    const VISIBLE: usize = 20;
    if fingerprint.chars().count() <= VISIBLE + 4 {
        return fingerprint.to_string();
    }
    let prefix: String = fingerprint.chars().take(VISIBLE).collect();
    format!("{prefix}…")
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
    // The description is the scanner's CLAIM — every asserting row states
    // whether it is a claim or a recorded observation, so the epistemic
    // status never depends on reading the adjacent ladder.
    lines.push(Line::styled(
        format!("claim · {}", claim_marker(detail.proof_tier)),
        theme::muted(),
    ));
    push_wrapped(&mut lines, &detail.title, width, "", theme::heading());
    lines
}

fn claim_marker(tier: crate::ui_view_models::ProofTier) -> &'static str {
    use crate::ui_view_models::ProofTier;
    match tier {
        ProofTier::RuntimeVerified => "runtime-verified",
        ProofTier::StaticLinked => "statically corroborated, not reproduced",
        ProofTier::Suspected => "unverified scanner assertion",
        ProofTier::Rejected => "refuted — kept for the record",
    }
}

fn push_detail_kv(lines: &mut Vec<Line<'static>>, key: &'static str, value: &str, width: usize) {
    if value.trim().is_empty() || value == "-" {
        return;
    }
    push_wrapped(lines, &format!("{key}: {value}"), width, "", theme::muted());
}

fn push_section_header(lines: &mut Vec<Line<'static>>, label: &'static str) {
    if !lines.last().is_some_and(is_blank_line) {
        lines.push(blank_line());
    }
    lines.push(section_line(label));
}

fn is_blank_line(line: &Line<'static>) -> bool {
    line.spans.iter().all(|span| span.content.trim().is_empty())
}

fn section_line(label: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled("── ", theme::subtle()),
        Span::styled(label, theme::label()),
        Span::styled(" ──", theme::subtle()),
    ])
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

fn push_optional_summary_line(
    lines: &mut Vec<Line<'static>>,
    value: &str,
    width: usize,
    prefix: &'static str,
    style: Style,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    let budget = width.saturating_sub(prefix.chars().count()).max(8);
    lines.push(Line::from(vec![
        Span::raw(prefix.to_string()),
        Span::styled(fit(value, budget), style),
    ]));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{
        ProofTier, SeverityTone, TriageSummaryModel, WORKBENCH_REPORT_COMMAND,
    };

    fn detail() -> FindingDetailModel {
        let mut detail = detail_claim();
        apply_detail_status(&mut detail);
        apply_detail_body(&mut detail);
        detail
    }

    fn detail_claim() -> FindingDetailModel {
        FindingDetailModel {
            alias: Some("F-0001".to_string()),
            identity_label: "FI-12345678".to_string(),
            severity_tone: SeverityTone::High,
            severity_label: "high".to_string(),
            title: "demo finding".to_string(),
            location: "src/app.rs:42".to_string(),
            rule: "demo.rule".to_string(),
            tool: "demo".to_string(),
            source_signature: "app.rs:42:demo-finding".to_string(),
            corroboration: "1".to_string(),
            fingerprint: "fp-demo".to_string(),
            run_label: "run:run-demo".to_string(),
            run_status: "status:completed".to_string(),
            run_tool: "tool:sast:scan".to_string(),
            run_model: "model:openai:gpt-test".to_string(),
            run_runtime: "runtime:codex".to_string(),
            run_kuzushi_version: "kuzushi:0.24.0-test".to_string(),
            revision_label: "rev:abc1234".to_string(),
            branch_label: "branch:main".to_string(),
            vuln_source_label: "analysis".to_string(),
            proof_label: "unverified".to_string(),
            proof_marker: "?",
            proof_tier: ProofTier::Suspected,
            proof_confidence: kuzushi_core::ProofConfidence::Unverified,
            proof_confidence_label: "unverified".to_string(),
            proof_state: "not recorded".to_string(),
            runtime_verification: "not run".to_string(),
            ..FindingDetailModel::default()
        }
    }

    fn apply_detail_status(detail: &mut FindingDetailModel) {
        detail.confidence = "-".to_string();
        detail.lifecycle_status = "candidate".to_string();
        detail.decision = "needs_review".to_string();
        detail.decision_source = "none".to_string();
        detail.decision_history = "no decision history loaded".to_string();
        detail.evidence_state = "evidence:1".to_string();
        detail.static_proof_label = "not recorded".to_string();
        detail.static_proof_explanation = "no static proof recorded".to_string();
        detail.runtime_label = "not verified".to_string();
        detail.runtime_explanation = "runtime verification has not run".to_string();
        detail.next_action_label = "validate".to_string();
        detail.next_command = Some("verify F-0001".to_string());
        detail.next_detail =
            "collect runtime proof or stronger source evidence before patching".to_string();
    }

    fn apply_detail_body(detail: &mut FindingDetailModel) {
        detail.evidence = vec![FindingEvidenceRow {
            origin: "observed capture evidence".to_string(),
            header: "source · conf 90 · src/app.rs:42".to_string(),
            snippet: "request reaches sink".to_string(),
            rationale: "tainted input".to_string(),
            capture: Some("http capture: request body recorded".to_string()),
        }];
        detail.message_lines = vec!["line 1".to_string()];
        detail.message_overflow = 2;
        detail.evidence_overflow = 3;
        detail.source_snippet = Some(crate::ui_view_models::SourceSnippetModel {
            start_line: 40,
            focus_line: 42,
            lines: vec![
                "fn handler(req: Request) {".to_string(),
                "    let name = req.param(\"name\");".to_string(),
                "    db.query(&format!(\"SELECT {name}\"));".to_string(),
                "}".to_string(),
            ],
            note: None,
        });
    }

    fn detail_text(report_command: Option<&'static str>) -> String {
        detail_text_for_width(&detail(), 80, report_command)
    }

    fn detail_text_for_width(
        detail: &FindingDetailModel,
        width: usize,
        report_command: Option<&'static str>,
    ) -> String {
        detail_lines_for_model(detail, width, report_command)
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

    /// Every asserting row states its epistemic status: the description is
    /// a claim (tiered), the source excerpt is an observation.
    #[test]
    fn detail_marks_the_claim_and_the_observation_explicitly() {
        let text = detail_text(None);

        assert!(
            text.contains("claim · unverified scanner assertion"),
            "{text}"
        );
        assert!(
            text.contains("SOURCE · observation (on-disk excerpt)"),
            "{text}"
        );
    }

    #[test]
    fn detail_lines_disclose_hidden_message_and_evidence_rows() {
        let text = detail_text(None);

        assert!(text.contains("CLAIM"), "{text}");
        assert!(text.contains("alias: F-0001"), "{text}");
        assert!(text.contains("STATUS"), "{text}");
        assert!(text.contains("severity: high"), "{text}");
        assert!(text.contains("lifecycle status: candidate"), "{text}");
        assert!(text.contains("evidence state: evidence:1"), "{text}");
        assert!(text.contains("proof summary: ? unverified"), "{text}");
        assert!(text.contains("current decision: needs_review"), "{text}");
        assert!(text.contains("ANALYSIS"), "{text}");
        assert!(text.contains("static proof: not recorded"), "{text}");
        assert!(text.contains("VERIFICATION"), "{text}");
        assert!(
            text.contains("runtime verification: not verified"),
            "{text}"
        );
        assert!(text.contains("DECISION"), "{text}");
        assert!(text.contains("PROVENANCE"), "{text}");
        assert_detail_provenance_lines(&text);
        assert!(!text.contains("SIGNALS"), "{text}");
        assert!(!text.contains("TRIAGE"), "{text}");
        assert!(text.contains("NEXT"), "{text}");
        assert!(text.contains("validate: `verify F-0001`"), "{text}");
        assert!(text.contains("origin: observed capture evidence"), "{text}");
        assert!(
            text.contains("http capture: request body recorded"),
            "{text}"
        );
        assert!(text.contains("… 2 more message lines"), "{text}");
        assert!(text.contains("… 3 more evidence rows"), "{text}");
    }

    #[test]
    fn detail_signposts_review_actions() {
        let text = detail_text(None);

        assert!(
            text.contains("decision <true-positive|false-positive> <reason>"),
            "{text}"
        );
        assert!(text.contains("dismiss <reason> <note>"), "{text}");
        assert!(
            text.contains("suppress <id> --reason <text> --days 90"),
            "{text}"
        );
    }

    fn assert_detail_provenance_lines(text: &str) {
        assert!(text.contains("run: run:run-demo"), "{text}");
        assert!(text.contains("run status: status:completed"), "{text}");
        assert!(text.contains("run tool: tool:sast:scan"), "{text}");
        assert!(text.contains("run model: model:openai:gpt-test"), "{text}");
        assert!(text.contains("run runtime: runtime:codex"), "{text}");
        assert!(
            text.contains("kuzushi version: kuzushi:0.24.0-test"),
            "{text}"
        );
        assert!(text.contains("revision: rev:abc1234"), "{text}");
        assert!(text.contains("branch: branch:main"), "{text}");
        assert!(text.contains("vuln source: analysis"), "{text}");
    }

    #[test]
    fn detail_sections_follow_review_order() {
        let text = detail_text(None);

        assert_sections_in_order(
            &text,
            &[
                "STATUS",
                "DECISION",
                "NEXT",
                "SOURCE",
                "EVIDENCE",
                "VERIFICATION",
                "ANALYSIS",
                "CLAIM",
                "SCANNER MESSAGE",
                "PROVENANCE",
            ],
        );
    }

    fn guard_dataflow_row() -> DataflowEvidenceRow {
        DataflowEvidenceRow {
            origin: "deep auditor (cpg-rs path)".to_string(),
            location: "src/users.ts:91".to_string(),
            kind: "guard".to_string(),
            note: "falsifying evidence · authz gate".to_string(),
        }
    }

    #[test]
    fn dataflow_section_renders_after_evidence_when_rows_exist() {
        let mut detail = detail();
        detail.dataflow_evidence = vec![guard_dataflow_row()];
        detail.dataflow_overflow = 2;
        let text = detail_text_for_width(&detail, 120, None);

        assert!(text.contains("AUDITED DATAFLOW"), "{text}");
        assert!(text.contains("guard · src/users.ts:91"), "{text}");
        assert!(text.contains("falsifying evidence · authz gate"), "{text}");
        assert!(text.contains("… 2 more dataflow rows"), "{text}");
        assert_sections_in_order(&text, &["EVIDENCE", "AUDITED DATAFLOW", "VERIFICATION"]);
    }

    #[test]
    fn empty_dataflow_rows_render_no_header() {
        let mut detail = detail();
        detail.dataflow_evidence = Vec::new();
        detail.dataflow_overflow = 0;
        let text = detail_text_for_width(&detail, 120, None);

        assert!(!text.contains("AUDITED DATAFLOW"), "{text}");
    }

    #[test]
    fn source_section_numbers_lines_and_marks_the_finding_line() {
        let text = detail_text(None);

        assert!(text.contains("SOURCE"), "{text}");
        assert!(text.contains("src/app.rs:42"), "{text}");
        assert!(
            text.contains("    40 │ fn handler(req: Request) {"),
            "{text}"
        );
        assert!(
            text.contains("  ▶ 42 │     db.query(&format!(\"SELECT {name}\"));"),
            "{text}"
        );
        assert!(text.contains("    43 │ }"), "{text}");
    }

    #[test]
    fn source_section_explains_an_unavailable_snippet_instead_of_vanishing() {
        let mut detail = detail();
        detail.source_snippet = Some(crate::ui_view_models::SourceSnippetModel {
            start_line: 42,
            focus_line: 42,
            lines: Vec::new(),
            note: Some("source unavailable · No such file or directory".to_string()),
        });
        let text = detail_text_for_width(&detail, 120, None);

        assert!(text.contains("SOURCE"), "{text}");
        assert!(
            text.contains("source unavailable · No such file or directory"),
            "{text}"
        );
    }

    #[test]
    fn detail_without_a_snippet_renders_no_source_section() {
        let mut detail = detail();
        detail.source_snippet = None;
        let text = detail_text_for_width(&detail, 120, None);

        assert!(!text.contains("SOURCE"), "{text}");
    }

    #[test]
    fn detail_decision_uses_review_decision_wording() {
        let mut detail = detail();
        detail.triage = Some(TriageSummaryModel {
            review_decision: "confirmed".to_string(),
            verdict: "true_positive".to_string(),
            confidence: "0.91".to_string(),
            author: "human".to_string(),
            source: "selected finding".to_string(),
            rationale: "source and sink are linked".to_string(),
        });
        detail.decision = "confirmed".to_string();
        detail.confidence = "91%".to_string();
        detail.decision_source = "selected finding".to_string();
        detail.decision_history = "latest loaded decision from selected finding".to_string();
        let text = detail_text_for_width(&detail, 120, None);

        assert!(
            text.contains(
                "review decision: confirmed · confidence 0.91 · by human · source selected finding"
            ),
            "{text}"
        );
        assert!(text.contains("current decision: confirmed"), "{text}");
        assert!(
            text.contains("decision history: latest loaded decision from selected finding"),
            "{text}"
        );
        assert!(
            text.contains("legacy triage verdict: true_positive"),
            "{text}"
        );
        assert!(text.contains("human review rationale: source and sink are linked"));
    }

    #[test]
    fn detail_decision_labels_automated_reasoning_as_model_generated() {
        let mut detail = detail();
        detail.triage = Some(TriageSummaryModel {
            review_decision: "confirmed".to_string(),
            verdict: "true_positive".to_string(),
            confidence: "0.72".to_string(),
            author: "auto".to_string(),
            source: "selected finding".to_string(),
            rationale: "model inferred source and sink are linked".to_string(),
        });
        let text = detail_text_for_width(&detail, 120, None);

        assert!(
            text.contains(
                "automated/model-generated review reasoning: model inferred source and sink are linked"
            ),
            "{text}"
        );
    }

    #[test]
    fn detail_actions_include_report_command_when_available() {
        let text = detail_text(Some(WORKBENCH_REPORT_COMMAND));

        assert!(text.contains("report: `report`"), "{text}");
        assert!(text.contains("validate: `verify F-0001`"), "{text}");
        assert!(text.contains("report:"), "{text}");
        assert!(!text.contains("o open in editor"), "{text}");
        assert!(!text.contains("proof state:"), "{text}");
        assert!(!text.contains("actions:"), "{text}");
    }

    fn assert_sections_in_order(text: &str, sections: &[&str]) {
        let mut start = 0;
        for section in sections {
            let offset = text[start..]
                .find(section)
                .unwrap_or_else(|| panic!("missing section {section} in:\n{text}"));
            start += offset + section.len();
        }
    }
}
