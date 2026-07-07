use super::*;

fn row_with_proof(
    proof_label: &str,
    proof_marker: &'static str,
    proof_tier: ProofTier,
) -> FindingListRow {
    FindingListRow {
        alias: "F-0001".to_string(),
        identity_label: "FI-12345678".to_string(),
        severity_tone: SeverityTone::High,
        severity_label: "HIGH".to_string(),
        title: "request reaches sink".to_string(),
        location: "crates/kuzushi-tui/src/app/example.rs:42".to_string(),
        run_label: "run:abc".to_string(),
        revision_label: "rev:def".to_string(),
        verdict: "tp".to_string(),
        confidence: "91%".to_string(),
        priority_label: "p:1".to_string(),
        lifecycle_status: "statically_supported".to_string(),
        decision: "confirmed".to_string(),
        decision_conflict: None,
        proof_label: proof_label.to_string(),
        proof_marker,
        proof_tier,
        proof_confidence: kuzushi_core::ProofConfidence::Likely,
        proof_confidence_label: "LIKELY".to_string(),
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

fn lines_text(lines: Vec<Line<'static>>) -> String {
    lines
        .into_iter()
        .flat_map(|line| line.spans)
        .map(|span| span.content.into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn finding_row_separates_review_signals_when_width_allows() {
    let row = row_with_proof("path-linked", "◇", ProofTier::StaticLinked);
    let text = row_text(&row, 120);

    assert!(text.contains("p:1"), "{text}");
    assert!(text.contains("status:statically_supported"), "{text}");
    assert!(text.contains("decision:confirmed"), "{text}");
    assert!(text.contains("proof:◇path-linked"), "{text}");
    assert!(text.contains("request reaches sink"), "{text}");
    assert!(!text.contains("example.rs:42"), "{text}");
    assert!(!text.contains("run:abc"), "{text}");
    assert!(!text.contains("rev:def"), "{text}");
}

fn finding_row_names_decision_conflict_when_width_allows() {
    let mut row = row_with_proof("path-linked", "◇", ProofTier::StaticLinked);
    row.decision = "rejected_false_positive".to_string();
    row.decision_conflict = Some("reappeared_after_rejection".to_string());

    let text = row_text(&row, 180);

    assert!(text.contains("decision:rejected_fp"), "{text}");
    assert!(text.contains("conflict:reappeared"), "{text}");
}

#[test]
fn finding_row_renders_identity_and_location_when_wide() {
    let row = row_with_proof("path-linked", "◇", ProofTier::StaticLinked);
    let text = row_text(&row, 220);

    assert!(text.contains("F-0001"), "{text}");
    assert!(text.contains("FI-12345678"), "{text}");
    assert!(text.contains("H"), "{text}");
    assert!(text.contains("p:1"), "{text}");
    assert!(text.contains("conf:91%"), "{text}");
    assert!(text.contains("status:statically_supported"), "{text}");
    assert!(text.contains("decision:confirmed"), "{text}");
    assert!(text.contains("proof:◇path-linked"), "{text}");
    assert!(text.contains("request reaches sink"), "{text}");
    assert!(
        text.contains("crates/kuzushi-tui/src/app/example.rs:42"),
        "{text}"
    );
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
    let text = row_text(&row, 72);

    assert!(text.contains("p:1 ?"), "{text}");
    assert!(!text.contains("example.rs:42"), "{text}");
}

#[test]
fn proof_legend_is_gated_until_findings_has_enough_rows() {
    assert!(!should_show_proof_legend(9, 80));
    assert!(!should_show_proof_legend(10, 71));
    assert!(should_show_proof_legend(10, 72));
}

#[test]
fn proof_legend_names_suspected_not_guess() {
    let text = line_text(proof_legend_line());

    assert!(text.contains("? suspected"), "{text}");
    assert!(!text.contains("guess"), "{text}");
}

#[test]
fn filtered_empty_state_names_active_filter_and_clear_command() {
    let text = lines_text(filtered_empty_lines(
        &FilteredFindingsEmptyState {
            expression: "decision:suppressed completeness:complete".to_string(),
        },
        "ledger: .kuzushi/v3/index.sqlite3",
    ));

    assert!(text.contains("filtered out"), "{text}");
    assert!(
        text.contains("active filter matched no rows: decision:suppressed completeness:complete"),
        "{text}"
    );
    assert!(text.contains("scanner findings were not changed"), "{text}");
    assert!(text.contains("findings"), "{text}");
    assert!(!text.contains("no findings yet"), "{text}");
}

fn line_text(line: Line<'static>) -> String {
    line.spans
        .into_iter()
        .map(|span| span.content.into_owned())
        .collect()
}
