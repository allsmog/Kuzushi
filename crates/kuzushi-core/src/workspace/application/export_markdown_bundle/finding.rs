use super::formatting::*;
use super::review::push_bundle_decision_basis;
use super::*;

pub(super) fn render_bundle_finding_markdown(
    record: &WorkspaceFindingExportRecord,
    finding: &Finding,
) -> String {
    let mut out = String::new();
    push_bundle_header(&mut out, record);
    push_bundle_relationships(&mut out, record);
    push_markdown_goals(&mut out, record);
    crate::workspace::application::export_lessons::push_markdown_lessons(&mut out, &record.lessons);
    push_bundle_security_context(&mut out, record);
    push_bundle_message(&mut out, finding);
    if !finding.evidence.is_empty() {
        out.push_str("## Evidence\n\n");
        for piece in &finding.evidence {
            push_bundle_evidence(&mut out, piece);
        }
    }
    out
}

fn push_bundle_relationships(out: &mut String, record: &WorkspaceFindingExportRecord) {
    if record.relationships.is_empty() {
        return;
    }
    out.push_str("## Recorded relationships\n\nGrouping is separate from finding verdicts. Recorded runs do not establish applicability at another source revision.\n\n");
    for relation in &record.relationships {
        out.push_str(&format!(
            "- **{:?} / {:?}, revision {}:** #{} to #{}. {}\n",
            relation.kind,
            relation.state,
            relation.revision,
            relation.from.finding_id,
            relation.to.finding_id,
            markdown_inline_text(&relation.note)
        ));
    }
    out.push('\n');
}

fn push_bundle_security_context(out: &mut String, record: &WorkspaceFindingExportRecord) {
    if !has_bundle_security_context(record) {
        return;
    }
    out.push_str("## Security context\n\n");
    push_optional_bundle_field(out, "Recommended change", record.recommendation.as_deref());
    push_optional_bundle_field(out, "Impact", record.impact.as_deref());
    push_optional_bundle_field(out, "Exploit scenario", record.exploit_scenario.as_deref());
    push_optional_bundle_field(out, "Category", record.category.as_deref());
    if record
        .preconditions
        .iter()
        .any(|value| !value.trim().is_empty())
    {
        out.push_str("- **Preconditions:**\n");
        for precondition in record
            .preconditions
            .iter()
            .filter(|value| !value.trim().is_empty())
        {
            out.push_str(&format!("  - {}\n", markdown_inline_text(precondition)));
        }
    }
    out.push('\n');
}

fn has_bundle_security_context(record: &WorkspaceFindingExportRecord) -> bool {
    [
        record.recommendation.as_deref(),
        record.impact.as_deref(),
        record.exploit_scenario.as_deref(),
        record.category.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| !value.trim().is_empty())
        || record
            .preconditions
            .iter()
            .any(|value| !value.trim().is_empty())
}

fn push_optional_bundle_field(out: &mut String, label: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        out.push_str(&format!("- **{label}:** {}\n", markdown_inline_text(value)));
    }
}

fn push_bundle_header(out: &mut String, record: &WorkspaceFindingExportRecord) {
    push_bundle_finding_summary(out, record);
    push_bundle_evidence_summary(out, record);
    push_bundle_analysis_summary(out, record);
    out.push_str(&format!(
        "- **Tool:** {}\n",
        markdown_inline_text(&record.tool)
    ));
    out.push_str(&format!(
        "- **Rule:** {}\n",
        markdown_code_span(&record.rule_id)
    ));
    out.push_str(&format!(
        "- **Fingerprint:** {}\n",
        markdown_code_span(&record.fingerprint)
    ));
    push_bundle_run_provenance(out, record);
    push_bundle_source_history(out, record);
    push_bundle_remediation(out, record);
    out.push_str(&format!(
        "- **Location:** {}\n\n",
        markdown_code_span(&format!(
            "{}:{}",
            record.location.file, record.location.start_line
        ))
    ));
}

fn push_bundle_finding_summary(out: &mut String, record: &WorkspaceFindingExportRecord) {
    out.push_str(&format!(
        "# {} · {}\n\n",
        record.alias,
        markdown_inline_text(&record.title)
    ));
    out.push_str(&format!(
        "- **Severity:** {}\n",
        markdown_inline_text(&record.severity)
    ));
    out.push_str(&format!(
        "- **Review decision:** {}\n",
        markdown_inline_text(&record.review_decision)
    ));
    push_bundle_decision_basis(out, record);
    if let Some(note) = record.observation_note.as_deref() {
        out.push_str(&format!(
            "- **Observation:** {}\n",
            markdown_inline_text(note)
        ));
    }
    if let Some(conflict) = record.review_decision_conflict.as_deref() {
        out.push_str(&format!(
            "- **Decision conflict:** {}\n",
            markdown_inline_text(conflict)
        ));
    }
    out.push_str(&format!(
        "- **Lifecycle status:** {}\n",
        markdown_inline_text(&record.lifecycle_status)
    ));
}

fn push_bundle_remediation(out: &mut String, record: &WorkspaceFindingExportRecord) {
    let Some(remediation) = record.remediation.as_ref() else {
        return;
    };
    out.push_str(&format!(
        "- **Remediation:** {} ({})\n",
        markdown_inline_text(&remediation.application_state),
        markdown_code_span(&remediation.application_id)
    ));
    out.push_str(&format!(
        "- **Empirically verified:** {}\n",
        remediation.empirically_verified
    ));
    out.push_str(&format!(
        "- **Patch run:** {} · diff {}\n",
        markdown_code_span(&remediation.patch_run_id),
        markdown_code_span(&remediation.diff_hash)
    ));
    if let Some(outcome) = remediation.reverify_outcome.as_deref() {
        out.push_str(&format!(
            "- **Re-verification:** {}",
            markdown_inline_text(outcome)
        ));
        if let Some(run_id) = remediation.reverify_run_id.as_deref() {
            out.push_str(&format!(" ({})", markdown_code_span(run_id)));
        }
        out.push('\n');
    }
    if !remediation.touched_paths.is_empty() {
        out.push_str(&format!(
            "- **Touched paths:** {}\n",
            remediation
                .touched_paths
                .iter()
                .map(|path| markdown_code_span(path))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn push_bundle_evidence_summary(out: &mut String, record: &WorkspaceFindingExportRecord) {
    out.push_str(&format!(
        "- **Evidence state:** {} ({} observed)\n",
        markdown_inline_text(&record.evidence.state),
        record.evidence.observed_count
    ));
    out.push_str(&format!(
        "- **Evidence origin:** observed={} code={} capture={} other={} model-generated-reasoning={} derived-source={} reasoning assertions={}\n",
        record.evidence.observed_evidence_present,
        record.evidence.observed_code_count,
        record.evidence.observed_capture_count,
        record.evidence.observed_other_count,
        record.evidence.model_generated_reasoning_count,
        record.evidence.derived_source_present,
        record.evidence.reasoning_assertion_count
    ));
}

fn push_bundle_analysis_summary(out: &mut String, record: &WorkspaceFindingExportRecord) {
    out.push_str(&format!(
        "- **Automated reasoning:** {}\n",
        record.analysis.automated_reasoning_present
    ));
    out.push_str(&format!(
        "- **Proof band:** {}\n",
        markdown_inline_text(&record.proof_confidence)
    ));
    out.push_str(&format!(
        "- **Static proof:** {} ({})\n",
        markdown_inline_text(&record.static_proof_label),
        markdown_inline_text(&record.static_proof_state)
    ));
    out.push_str(&format!(
        "- **Verification:** {}\n",
        markdown_inline_text(&record.verification.label)
    ));
    if let Some(identity) = &record.verification.source_identity {
        let identity =
            serde_json::to_string(identity).unwrap_or_else(|_| "unavailable".to_string());
        out.push_str(&format!(
            "- **Verification source:** {}\n",
            markdown_code_span(&identity)
        ));
    }
    if let Some(reproducer) = &record.verification.reproducer {
        out.push_str(&format!(
            "- **Verification reproducer:** {} ({})\n",
            markdown_code_span(reproducer.hash.as_str()),
            markdown_inline_text(reproducer.kind.as_str())
        ));
    }
}

fn push_bundle_run_provenance(out: &mut String, record: &WorkspaceFindingExportRecord) {
    let Some(run_id) = record.provenance.run_id.as_deref() else {
        return;
    };
    out.push_str(&format!("- **Run:** {}", markdown_code_span(run_id)));
    if let Some(status) = record.provenance.run_status.as_deref() {
        out.push_str(&format!(" ({})", markdown_inline_text(status)));
    }
    if let Some(model) = record.provenance.model.as_deref() {
        out.push_str(&format!(" model {}", markdown_code_span(model)));
    }
    out.push('\n');
}

fn push_bundle_source_history(out: &mut String, record: &WorkspaceFindingExportRecord) {
    let history = &record.provenance.source_history;
    if history.is_empty() {
        return;
    }
    out.push_str("\n### Recorded source summaries\n\nThese are recorded source summaries, not a complete observation log.\n\n");
    for source in history.iter().take(8) {
        out.push_str(&format!(
            "- **Source:** {} · {}\n",
            markdown_inline_text(&source.tool),
            markdown_code_span(&source.source_signature)
        ));
        out.push_str(&format!(
            "  - First observation: {} · {}\n",
            markdown_code_span(&source.first_scan_id),
            source_date(&source.first_seen_at)
        ));
        out.push_str(&format!(
            "  - Latest observation: {} · {}\n",
            markdown_code_span(&source.last_scan_id),
            source_date(&source.last_seen_at)
        ));
    }
    if history.len() > 8 {
        out.push_str(&format!(
            "\n{} more source summaries are preserved in the bundle manifest.\n",
            history.len() - 8
        ));
    }
}

fn source_date(recorded: &str) -> String {
    let label = recorded
        .parse::<u64>()
        .map(crate::session_transcript::utc_timestamp_from_unix_seconds)
        .unwrap_or_else(|_| recorded.to_string());
    markdown_inline_text(&label)
}

#[cfg(test)]
mod source_history_tests {
    use super::*;

    #[test]
    fn markdown_source_summaries_are_bounded_and_capture_text_cannot_add_lines() {
        let mut record = WorkspaceFindingExportRecord::default();
        let source = crate::findings::FindingSource {
            tool: "owned\n# forged".into(),
            vuln_source: None,
            source_signature: "note.md:1".into(),
            first_scan_id: "first".into(),
            last_scan_id: "latest".into(),
            first_seen_at: "1000".into(),
            last_seen_at: "unknown".into(),
        };
        record.provenance.source_history = vec![source; 9];
        let mut text = String::new();
        push_bundle_source_history(&mut text, &record);
        assert_eq!(text.matches("**Source:**").count(), 8);
        assert!(text.contains("First observation: `first`"));
        assert!(text.contains("Latest observation: `latest`"));
        assert!(text.contains("1970-01-01"));
        assert!(text.contains("1 more source summaries"));
        assert!(!text.contains("\n# forged"));
        assert_eq!(record.provenance.source_history.len(), 9);
    }

    #[test]
    fn absent_source_history_does_not_invent_entries() {
        let mut text = String::new();
        push_bundle_source_history(&mut text, &WorkspaceFindingExportRecord::default());
        assert!(text.is_empty());
    }
}

fn push_bundle_message(out: &mut String, finding: &Finding) {
    out.push_str("## Message\n\n");
    out.push_str(&fenced_snippet_block(&finding.message));
}

fn push_bundle_evidence(out: &mut String, evidence: &FindingEvidence) {
    out.push_str(&format!(
        "### {kind} · {file}:{line}\n\n",
        kind = markdown_inline_text(&evidence.kind),
        file = markdown_inline_text(&evidence.file_path),
        line = evidence.line
    ));
    out.push_str(&format!(
        "_Origin: {}_\n\n",
        markdown_inline_text(finding_evidence_origin_label(evidence))
    ));
    if !evidence.snippet.is_empty() {
        out.push_str(&fenced_snippet_block(&evidence.snippet));
    }
    if !evidence.rationale.is_empty() {
        out.push_str(&fenced_snippet_block(&evidence.rationale));
    }
}

pub(super) fn push_markdown_goals(out: &mut String, record: &WorkspaceFindingExportRecord) {
    if record.goal_assessments.is_empty() {
        return;
    }
    out.push_str("## Goal relevance history\n\nOperator priorities, separate from finding verdicts. Each assessment applies only to its recorded brief and observation. Later source revisions require independent review.\n\n");
    for assessment in &record.goal_assessments {
        let reason = markdown_inline_text(&assessment.reason);
        let brief_text = markdown_inline_text(&assessment.brief_text);
        out.push_str(&format!("- **{}**, assessment v{}: {}\n  Brief {} v{}, object {}. Finding generation #{}, observation {}, source snapshot {}, run {}.\n  Reviewed goal: {brief_text}\n",
            assessment.relevance.label(), assessment.revision, reason,
            assessment.brief_ref.brief_id, assessment.brief_ref.revision, assessment.brief_ref.object.hash,
            assessment.basis.finding_id, assessment.basis.observation_seq, assessment.basis.snapshot_hash, assessment.basis.run_id));
    }
    out.push('\n');
}
