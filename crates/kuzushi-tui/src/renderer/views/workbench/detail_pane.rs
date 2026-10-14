//! Finding detail line builder for the Workbench DETAILS pane.

use super::*;
use crate::ui_view_models::{
    FindingDetailModel, FindingEvidenceRow, ProofTier, ReviewYieldDetailModel,
    ReviewYieldSignalViewModel, REVIEW_YIELD_ADVISORY_LINE_1, REVIEW_YIELD_ADVISORY_LINE_2,
};
use kuzushi_core::findings::DataflowEvidenceRow;
use ratatui::prelude::{Line, Span};
use ratatui::style::Style;

mod review;
pub(super) use review::review_detail_lines;

fn push_observation_gap(
    lines: &mut Vec<Line<'static>>,
    detail: &FindingDetailModel,
    budget: usize,
) {
    if let Some(note) = &detail.observation_gap {
        push_section_header(lines, "OBSERVATION GAP");
        push_wrapped(lines, note, budget, "  ", theme::warn());
    }
}

fn push_source_section(lines: &mut Vec<Line<'static>>, detail: &FindingDetailModel, budget: usize) {
    let Some(snippet) = detail.source_snippet.as_ref() else {
        return;
    };
    push_section_header(lines, source_section_label(budget));
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

fn source_section_label(budget: usize) -> &'static str {
    if budget < 42 {
        "SOURCE · observed excerpt"
    } else {
        "SOURCE · observation (on-disk excerpt)"
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

fn push_review_action_lines(lines: &mut Vec<Line<'static>>, budget: usize) {
    for action in [
        "triage: `decision <confirmed|deferred|needs_review> <reason>`",
        "false positive: `dismiss false_positive <note>`",
        "suppression rule: `suppress <id> --reason <text> --days 90`",
    ] {
        push_wrapped(lines, action, budget, "  ", theme::muted());
    }
}

fn push_recorded_decision(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    row: &crate::ui_view_models::DecisionHistoryRow,
    budget: usize,
) {
    push_wrapped(
        lines,
        &format!(
            "{label}: {} · {} · {}",
            row.verdict, row.author, row.created_at
        ),
        budget,
        "  ",
        theme::label(),
    );
    push_wrapped(lines, &row.rationale, budget, "    ", theme::muted());
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

/// The advisory review-yield explanation, below verification truth and above
/// the analysis narrative — it describes how reviewers ruled on findings like
/// this one, never what is true about this one.
///
/// `None` renders nothing, header included: an operator who did not turn the
/// signal on must not see a section implying one is being withheld. Both
/// states carry the same two advisory lines, because the numbers and the
/// message are equally easy to over-read.
fn push_review_yield_section(
    lines: &mut Vec<Line<'static>>,
    review_yield: Option<&ReviewYieldDetailModel>,
    budget: usize,
) {
    let Some(review_yield) = review_yield else {
        return;
    };
    push_section_header(lines, "REVIEW YIELD");
    match review_yield {
        ReviewYieldDetailModel::Signal(signal) => push_review_yield_signal(lines, signal, budget),
        ReviewYieldDetailModel::Unavailable { message } => {
            push_wrapped(lines, message, budget, "  ", theme::muted());
        }
    }
    push_wrapped(
        lines,
        REVIEW_YIELD_ADVISORY_LINE_1,
        budget,
        "  ",
        theme::muted(),
    );
    push_wrapped(
        lines,
        REVIEW_YIELD_ADVISORY_LINE_2,
        budget,
        "  ",
        theme::muted(),
    );
}

fn push_review_yield_signal(
    lines: &mut Vec<Line<'static>>,
    signal: &ReviewYieldSignalViewModel,
    budget: usize,
) {
    push_review_yield_row(
        lines,
        "historical positive rate",
        &signal.rate_label,
        budget,
    );
    push_review_yield_row(
        lines,
        "prior reviewed examples",
        &signal.support_label,
        budget,
    );
    push_review_yield_row(lines, "95% interval", &signal.interval_label, budget);
    push_review_yield_row(lines, "outcome entropy", &signal.entropy_label, budget);
    // Directly under the two numbers it orders by, so the claim is read next
    // to its evidence rather than as a headline over the whole section.
    if let Some(context) = signal.learn_context {
        push_wrapped(lines, context, budget, "  ", theme::muted());
    }
    push_review_yield_row(lines, "model", &signal.model_label, budget);
    push_review_yield_path(lines, &signal.path_steps, budget);
}

/// The splits the finding took. An empty path is a root leaf: the model made
/// no comparison at all, and saying so beats an empty list.
fn push_review_yield_path(lines: &mut Vec<Line<'static>>, path_steps: &[String], budget: usize) {
    if path_steps.is_empty() {
        push_wrapped(
            lines,
            "decision path: none — the model split on nothing",
            budget,
            "  ",
            theme::muted(),
        );
        return;
    }
    push_wrapped(lines, "decision path", budget, "  ", theme::muted());
    for step in path_steps {
        push_wrapped(lines, step, budget, "    ", theme::muted());
    }
}

fn push_review_yield_row(
    lines: &mut Vec<Line<'static>>,
    key: &'static str,
    value: &str,
    budget: usize,
) {
    push_wrapped(
        lines,
        &format!("{key}: {value}"),
        budget,
        "  ",
        theme::muted(),
    );
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
    push_detail_kv(lines, "rule", &detail.rule, budget);
    push_detail_kv(lines, "location", &detail.location, budget);
    push_detail_kv(lines, "producing tool", &detail.tool, budget);
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
    push_wrapped(
        &mut lines,
        &format!("claim · {}", claim_marker(detail)),
        width,
        "",
        theme::muted(),
    );
    push_wrapped(&mut lines, &detail.title, width, "", theme::heading());
    lines
}

fn claim_marker(detail: &FindingDetailModel) -> &'static str {
    if detail.proof_confidence_label == "suppressed" {
        return "suppressed; evidence remains recorded";
    }
    proof_claim_marker(detail.proof_tier)
}

fn proof_claim_marker(tier: crate::ui_view_models::ProofTier) -> &'static str {
    use crate::ui_view_models::ProofTier;
    match tier {
        ProofTier::RuntimeVerified => "runtime-verified",
        ProofTier::StaticLinked => "statically corroborated, not reproduced",
        ProofTier::Suspected => "unverified scanner assertion",
        ProofTier::Rejected => "refuted; kept for the record",
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

    pub(super) fn detail() -> FindingDetailModel {
        let mut detail = detail_claim();
        apply_detail_status(&mut detail);
        apply_detail_body(&mut detail);
        detail
    }

    #[test]
    fn observation_gap_precedes_decision_and_keeps_both_run_references() {
        for width in [36, 56, 76, 92, 116, 156] {
            let mut finding = detail();
            finding.observation_gap = Some("Not observed in run later-scan; last observed in run older-scan. Absence does not establish a fix.".to_string());
            let lines = review_detail_lines(&finding, width);
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.find("OBSERVATION GAP").unwrap() < text.find("DECISION").unwrap());
            let words = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(words.contains("Absence does not establish a fix."));
            assert!(words.contains("later-scan") && words.contains("older-scan"));
            assert!(
                lines.iter().all(|line| line.width() <= width),
                "width {width}: {:?}",
                lines
                    .iter()
                    .filter(|line| line.width() > width)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
        }
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

    pub(super) fn detail_text_for_width(
        detail: &FindingDetailModel,
        width: usize,
        _report_command: Option<&'static str>,
    ) -> String {
        review_detail_lines(detail, width)
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
    fn suppressed_claim_retains_evidence_without_implying_refutation() {
        let mut finding = detail();
        finding.proof_tier = ProofTier::Rejected;
        finding.proof_confidence_label = "suppressed".into();
        for width in [36, 56, 76, 92, 116, 156] {
            let lines = review_detail_lines(&finding, width);
            let text = lines
                .iter()
                .map(|line| {
                    line.spans
                        .iter()
                        .map(|span| span.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("claim · suppressed"), "{width}: {text}");
            assert!(!text.contains("refuted"), "{width}: {text}");
            assert!(text.contains("needs_review"), "{width}: {text}");
            for line in detail_title_lines(&finding, width) {
                assert!(line.width() <= width, "{line:?}");
            }
        }
    }

    #[test]
    fn detail_lines_disclose_hidden_message_and_evidence_rows() {
        let text = detail_text(None);

        assert!(text.contains("verdict: needs_review"), "{text}");
        assert!(text.contains("DECISION"), "{text}");
        assert!(text.contains("PROVENANCE"), "{text}");
        assert_detail_provenance_lines(&text);
        assert!(text.contains("REVIEW ACTIONS"), "{text}");
        assert!(!text.contains("verify F-0001"), "{text}");
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
            text.contains("decision <confirmed|deferred|needs_review> <reason>"),
            "{text}"
        );
        assert!(text.contains("dismiss false_positive <note>"), "{text}");
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
                "DECISION",
                "SOURCE",
                "EVIDENCE",
                "REVIEW ACTIONS",
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
        assert_sections_in_order(&text, &["EVIDENCE", "AUDITED DATAFLOW", "REVIEW ACTIONS"]);
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

        assert!(text.contains("verdict: confirmed"), "{text}");
        assert!(text.contains("author: human"), "{text}");
        assert!(text.contains("source and sink are linked"), "{text}");
        assert!(!text.contains("decision score"), "{text}");
        assert!(!text.contains("legacy triage"), "{text}");
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

        assert!(text.contains("author: auto"), "{text}");
        assert!(
            text.contains("model inferred source and sink are linked"),
            "{text}"
        );
        assert!(text.contains("author-reported confidence: 0.72"), "{text}");
    }

    #[test]
    fn detail_actions_include_report_command_when_available() {
        let text = detail_text(Some(WORKBENCH_REPORT_COMMAND));

        assert!(
            text.contains("report · export findings and decisions"),
            "{text}"
        );
        assert!(!text.contains("verify F-0001"), "{text}");
        assert!(!text.contains("before patching"), "{text}");
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

#[cfg(test)]
mod review_yield_tests {
    use super::tests::detail_text_for_width;
    use super::*;
    use crate::renderer::surface_lints::{
        lint_duplication, lint_jargon, lint_separators_and_truncation, SurfaceLine,
    };
    use crate::ui_view_models::{FindingDetailModel, ReviewYieldSignalViewModel};

    fn signal_view() -> ReviewYieldSignalViewModel {
        ReviewYieldSignalViewModel {
            rate_label: "74%".to_string(),
            support_label: "42 (31 confirmed · 11 rejected)".to_string(),
            interval_label: "59%–85%".to_string(),
            entropy_label: "0.83 bits".to_string(),
            model_label: "blake3:18655b7ee138…".to_string(),
            learn_context: None,
            path_steps: vec![
                "static_proof = source_sink_linked".to_string(),
                "distinct_tools > 1".to_string(),
            ],
        }
    }

    fn detail_with(review_yield: Option<ReviewYieldDetailModel>) -> FindingDetailModel {
        FindingDetailModel {
            review_yield,
            ..FindingDetailModel::default()
        }
    }

    fn text_of(review_yield: Option<ReviewYieldDetailModel>) -> String {
        detail_text_for_width(&detail_with(review_yield), 80, None)
    }

    /// Every rendering of the section an operator can reach, so the copy
    /// checks below cover the whole surface rather than one happy case.
    fn every_rendered_variant() -> Vec<String> {
        let mut variants = vec![
            text_of(Some(ReviewYieldDetailModel::Signal(signal_view()))),
            text_of(Some(ReviewYieldDetailModel::Signal(
                ReviewYieldSignalViewModel {
                    path_steps: Vec::new(),
                    ..signal_view()
                },
            ))),
            text_of(Some(ReviewYieldDetailModel::Signal(
                ReviewYieldSignalViewModel {
                    learn_context: Some(crate::ui_view_models::REVIEW_YIELD_LEARN_CONTEXT),
                    ..signal_view()
                },
            ))),
        ];
        for message in [
            "not scored yet — open this finding from the review queue to compute its signal",
            "the signal is turned off for this session",
            "no model is configured — nothing was scored",
            "the model file failed its integrity check — signal unavailable",
            "the model file format is not supported — signal unavailable",
            "the model expects a different set of inputs — signal unavailable",
            "this finding lacks a required input (distinct_tools) — signal unavailable",
            "tool_family is novel, which the model never saw in training — signal unavailable",
            "only 3 prior reviewed examples match this finding, below this model's evidence floor — no rate is shown",
            "this finding is outside the model's known data (depth guard exceeded) — signal unavailable",
            "this finding has no durable identity, so no review history joins to it",
            "no stored record of this finding exists yet — rescan the target to create one",
            "this finding's stored record could not be read — signal unavailable",
        ] {
            variants.push(text_of(Some(ReviewYieldDetailModel::Unavailable {
                message: message.to_string(),
            })));
        }
        variants
    }

    /// The numbers and their labels, plus the two sentences that keep them
    /// from being read as a verdict.
    #[test]
    fn review_yield_section_renders_signal_with_required_advisory() {
        let text = text_of(Some(ReviewYieldDetailModel::Signal(signal_view())));

        assert!(text.contains("REVIEW YIELD"), "{text}");
        assert!(text.contains("historical positive rate: 74%"), "{text}");
        assert!(
            text.contains("prior reviewed examples: 42 (31 confirmed · 11 rejected)"),
            "{text}"
        );
        assert!(text.contains("95% interval: 59%–85%"), "{text}");
        assert!(text.contains("outcome entropy: 0.83 bits"), "{text}");
        assert!(text.contains("model: blake3:18655b7ee138…"), "{text}");
        assert!(text.contains("decision path"), "{text}");
        assert!(text.contains("static_proof = source_sink_linked"), "{text}");
        assert!(text.contains("distinct_tools > 1"), "{text}");
        assert!(text.contains(REVIEW_YIELD_ADVISORY_LINE_1), "{text}");
        assert!(text.contains(REVIEW_YIELD_ADVISORY_LINE_2), "{text}");
    }

    /// The refusal is as easy to over-read as a number, so it carries the same
    /// two sentences.
    #[test]
    fn review_yield_unavailable_state_renders_message_with_advisory() {
        let text = text_of(Some(ReviewYieldDetailModel::Unavailable {
            message: "no model is configured — nothing was scored".to_string(),
        }));

        assert!(text.contains("REVIEW YIELD"), "{text}");
        assert!(
            text.contains("no model is configured — nothing was scored"),
            "{text}"
        );
        assert!(text.contains(REVIEW_YIELD_ADVISORY_LINE_1), "{text}");
        assert!(text.contains(REVIEW_YIELD_ADVISORY_LINE_2), "{text}");
    }

    /// An operator who did not turn the signal on must not learn it exists
    /// from an empty section implying a number is being withheld.
    #[test]
    fn review_yield_section_is_absent_when_the_signal_is_off() {
        let text = text_of(None);

        assert!(!text.contains("REVIEW YIELD"), "{text}");
        assert!(!text.contains(REVIEW_YIELD_ADVISORY_LINE_1), "{text}");
    }

    /// A root leaf split on nothing. An empty list under "decision path" would
    /// read as a truncation.
    #[test]
    fn an_empty_decision_path_says_the_model_split_on_nothing() {
        let text = text_of(Some(ReviewYieldDetailModel::Signal(
            ReviewYieldSignalViewModel {
                path_steps: Vec::new(),
                ..signal_view()
            },
        )));

        assert!(
            text.contains("decision path: none — the model split on nothing"),
            "{text}"
        );
    }

    /// The standing rendered-surface lints, run over every variant of this
    /// section rather than only the ones the seeded plain corpus happens to
    /// reach.
    #[test]
    fn review_yield_copy_passes_rendered_surface_lints() {
        for (index, text) in every_rendered_variant().into_iter().enumerate() {
            let corpus: Vec<SurfaceLine> = text
                .lines()
                .enumerate()
                .map(|(number, line)| SurfaceLine {
                    source: format!("review-yield:{index}"),
                    number: number + 1,
                    text: line.to_string(),
                })
                .collect();
            let mut violations = lint_jargon(&corpus);
            violations.extend(lint_duplication(&corpus));
            violations.extend(lint_separators_and_truncation(&corpus));
            assert!(
                violations.is_empty(),
                "{}",
                violations
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }

    /// The two claims this feature must never make. A historical reviewer
    /// outcome is not a probability that the code is vulnerable, and a model
    /// confirms nothing.
    #[test]
    fn review_yield_copy_never_claims_probability_or_model_confirmation() {
        for text in every_rendered_variant() {
            let lower = text.to_lowercase();
            assert!(!lower.contains("vulnerability probability"), "{text}");
            assert!(!lower.contains("confirmed by model"), "{text}");
            assert!(!lower.contains("probability"), "{text}");
            assert!(!lower.contains("watermark"), "{text}");
        }
    }

    /// Learn mode adds one sentence, directly under the two numbers it orders
    /// by, and it names the *model's* gap rather than doubt about the finding.
    /// The advisory pair still closes the section.
    #[test]
    fn learn_context_renders_under_the_numbers_it_explains() {
        let text = text_of(Some(ReviewYieldDetailModel::Signal(
            ReviewYieldSignalViewModel {
                learn_context: Some(crate::ui_view_models::REVIEW_YIELD_LEARN_CONTEXT),
                ..signal_view()
            },
        )));

        let body = section_body(&text);
        let entropy = body
            .iter()
            .position(|line| line.contains("outcome entropy"))
            .expect("the entropy row renders");
        let context = body
            .iter()
            .position(|line| line.contains("least evidence about"))
            .unwrap_or_else(|| panic!("no learn line in:\n{text}"));
        let model = body
            .iter()
            .position(|line| line.contains("model: blake3"))
            .expect("the model row renders");

        assert!(entropy < context && context < model, "{text}");
        assert!(
            text.contains("the model has least evidence about"),
            "{text}"
        );
    }

    /// The section's content lines, between the shared `── REVIEW YIELD ──`
    /// rule and the blank line that separates the next section header.
    fn section_body(text: &str) -> Vec<String> {
        text.lines()
            .skip_while(|line| !line.contains("REVIEW YIELD"))
            .skip(1)
            .take_while(|line| !line.contains("──"))
            .filter(|line| !line.trim().is_empty())
            .map(ToString::to_string)
            .collect()
    }

    /// Plain output strips styles and nothing else. A body whose meaning
    /// depended on colour or box drawing would go silent on a scripted shell,
    /// so every label and number is plain text.
    #[test]
    fn review_yield_body_carries_no_style_only_or_box_drawing_meaning() {
        for text in every_rendered_variant() {
            let body = section_body(&text);
            assert!(!body.is_empty(), "{text}");
            for line in body {
                assert!(!line.contains('\u{1b}'), "{line}");
                for glyph in ['│', '─', '╭', '╮', '╰', '╯', '▶', '▼'] {
                    assert!(!line.contains(glyph), "{glyph} in {line}");
                }
            }
        }
    }

    /// The advisory sentences close the section in every state, so they are
    /// never separated from the number or message they qualify.
    #[test]
    fn both_advisory_lines_close_every_rendering_of_the_section() {
        for text in every_rendered_variant() {
            let body = section_body(&text);
            let tail: Vec<String> = body
                .iter()
                .rev()
                .take(2)
                .map(|line| line.trim().to_string())
                .collect();
            assert_eq!(
                tail,
                vec![
                    REVIEW_YIELD_ADVISORY_LINE_2.to_string(),
                    REVIEW_YIELD_ADVISORY_LINE_1.to_string()
                ],
                "{text}"
            );
        }
    }
}
