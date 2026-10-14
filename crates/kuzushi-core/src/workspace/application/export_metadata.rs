use super::*;

pub(in crate::workspace::application) fn workspace_export_metadata_value(
    format: WorkspaceExportFormat,
    options: &WorkspaceExportOptions,
    included_count: usize,
    total_count: usize,
) -> serde_json::Value {
    let mut metadata = json!({
        "format": format.as_str(),
        "projection": "WorkspaceFindingExportRecord",
        "kuzushiVersion": env!("CARGO_PKG_VERSION"),
        "completeness": options.completeness.as_str(),
        "includedCount": included_count,
        "totalCount": total_count,
        "omittedFields": workspace_export_omitted_fields(format),
        "findingSelection": match options.campaign_id.as_deref() {
            Some(id) => json!({"kind": "study", "campaignId": id}),
            None => json!({"kind": "workspace-history"}),
        },
    });
    if let Some(review_yield) = review_yield_metadata_value(options.review_yield.as_ref()) {
        metadata["reviewYield"] = review_yield;
    }
    metadata
}

/// The review-yield block, present only when a session actually ran with the
/// signal armed.
///
/// `orderingInfluence` is stated because it is easy to misread: export row
/// order is keyed off the severity-major alias order and is never model-ordered,
/// in any mode. What the block discloses is the posture the operator reviewed
/// under, not a claim about these rows.
fn review_yield_metadata_value(
    provenance: Option<&ReviewYieldExportProvenance>,
) -> Option<serde_json::Value> {
    let provenance = provenance?;
    if provenance.mode == crate::config::ReviewYieldMode::Off {
        return None;
    }
    Some(json!({
        "mode": provenance.mode.label(),
        "modelId": provenance.model_id,
        "orderingInfluence": ordering_influence(provenance.mode),
    }))
}

fn ordering_influence(mode: crate::config::ReviewYieldMode) -> &'static str {
    if mode.orders_rows() {
        "review-display-only"
    } else {
        "none"
    }
}

const VULN_FINDINGS_OMITTED: &[&str] = &[
    "reviewDecisionBasis",
    "lessons",
    "relationships",
    "identityId",
    "priority",
    "lifecycleStatus",
    "evidence",
    "analysis",
    "staticProofState",
    "verification",
    "provenance",
    "references",
];

const CSV_OMITTED: &[&str] = &[
    "reviewDecisionBasis",
    "lessons",
    "cwe",
    "reviewDecisionReason",
    "snoozedUntil",
    "evidence.sourceCount",
    "evidence.rawHttpBlobPresent",
    "analysis.humanReviewPresent",
    "analysis.importedReviewPresent",
    "staticProofLabel",
    "verification.verdict",
    "verification.proofLevel",
    "verification.backend",
    "verification.language",
    "verification.sourceIdentity",
    "verification.reproducer",
    "provenance.runtimePlatform",
    "references",
    "message",
    "relationships",
];

const MARKDOWN_BUNDLE_OMITTED: &[&str] = &[
    "cwe",
    "identityId",
    "kind",
    "confidence",
    "priority",
    "triageState",
    "dismissal",
    "reviewDecisionReason",
    "reviewDecisionAuthor",
    "triageVerdict",
    "suppressed",
    "snoozedUntil",
    "location.endLine",
    "evidence.sourceCount",
    "evidence.rawHttpBlobPresent",
    "evidence.evidenceConfidenceMax",
    "analysis.staticProofRecorded",
    "analysis.humanReviewPresent",
    "analysis.importedReviewPresent",
    "verification.verdict",
    "verification.proofLevel",
    "verification.backend",
    "verification.language",
    "vulnSource",
    "sourceSignature",
    "corroborationCount",
    // The bundle renders the run reference from `provenance.runId`; the
    // top-level `runId` field itself is not projected into it.
    "runId",
    "provenance.tool",
    "provenance.vulnSource",
    "provenance.sourceSignature",
    "provenance.corroborationCount",
    "provenance.kuzushiVersion",
    "provenance.runtimePlatform",
    "remediation.findingScanId",
    "references",
];

pub fn workspace_export_omitted_fields(format: WorkspaceExportFormat) -> Vec<&'static str> {
    match format {
        WorkspaceExportFormat::Json | WorkspaceExportFormat::Jsonl => Vec::new(),
        WorkspaceExportFormat::VulnFindings => VULN_FINDINGS_OMITTED.to_vec(),
        WorkspaceExportFormat::Csv => CSV_OMITTED.to_vec(),
        WorkspaceExportFormat::Sarif => vec!["references"],
        WorkspaceExportFormat::MarkdownBundle => MARKDOWN_BUNDLE_OMITTED.to_vec(),
    }
}

#[cfg(test)]
mod source_basis_tests {
    use super::*;

    #[test]
    fn unchanged_row_formats_disclose_the_omitted_source_basis() {
        for format in [
            WorkspaceExportFormat::Csv,
            WorkspaceExportFormat::VulnFindings,
        ] {
            assert!(workspace_export_omitted_fields(format).contains(&"reviewDecisionBasis"));
        }
        for format in [
            WorkspaceExportFormat::Json,
            WorkspaceExportFormat::Jsonl,
            WorkspaceExportFormat::Sarif,
            WorkspaceExportFormat::MarkdownBundle,
        ] {
            assert!(!workspace_export_omitted_fields(format).contains(&"reviewDecisionBasis"));
        }
    }
}
