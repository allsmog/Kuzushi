use super::*;

pub(in crate::workspace::application) fn workspace_export_metadata_value(
    format: WorkspaceExportFormat,
    options: WorkspaceExportOptions,
    included_count: usize,
    total_count: usize,
) -> serde_json::Value {
    json!({
        "format": format.as_str(),
        "projection": "WorkspaceFindingExportRecord",
        "kuzushiVersion": env!("CARGO_PKG_VERSION"),
        "completeness": options.completeness.as_str(),
        "includedCount": included_count,
        "totalCount": total_count,
        "omittedFields": workspace_export_omitted_fields(format),
    })
}

const VULN_FINDINGS_OMITTED: &[&str] = &[
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
    "provenance.runtimePlatform",
    "references",
    "message",
];

const MARKDOWN_BUNDLE_OMITTED: &[&str] = &[
    "cwe",
    "identityId",
    "confidence",
    "priority",
    "reviewDecisionReason",
    "reviewDecisionAuthor",
    "triageVerdict",
    "snoozedUntil",
    "evidence.sourceCount",
    "evidence.rawHttpBlobPresent",
    "analysis.importedReviewPresent",
    "sourceSignature",
    "corroborationCount",
    "provenance.runtimePlatform",
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
