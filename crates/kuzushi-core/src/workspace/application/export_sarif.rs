//! M1 §1.4 — SARIF 2.1.0 export. One `runs[]` entry per `Finding.tool`,
//! severity → level map, fingerprints carried as `kuzushi/v1`. Lives in
//! its own module to keep `export_workspace_findings.rs` under the
//! 300-line per-file limit enforced by the CRAP-risk gate.

use super::export_metadata::workspace_export_metadata_value;
use super::export_projection_model::WorkspaceFindingExportRecord;
use super::*;
use std::collections::BTreeMap;

const KUZUSHI_INFORMATION_URI: &str = "https://github.com/allsmog/Kuzushi";

pub(crate) fn findings_to_sarif(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    options: WorkspaceExportOptions,
    total_count: usize,
) -> Result<String> {
    findings_to_sarif_with_benchmark_spend(workspace, records, options, total_count, None, None)
}

pub(in crate::workspace::application) struct SarifBenchmarkSpend {
    pub run_id: String,
    pub total_cost_usd: f64,
    pub models: Vec<String>,
    pub llm_call_count: usize,
    pub llm_audit_complete: bool,
    pub config_hash: Option<String>,
}

pub(in crate::workspace::application) fn findings_to_sarif_with_benchmark_spend(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    options: WorkspaceExportOptions,
    total_count: usize,
    benchmark_spend: Option<&SarifBenchmarkSpend>,
    scan_run_id: Option<&str>,
) -> Result<String> {
    let metadata = workspace_export_metadata_value(
        WorkspaceExportFormat::Sarif,
        options,
        records.len(),
        total_count,
    );
    let mut runs = group_findings_by_tool(records)
        .into_iter()
        .map(|(tool, tool_records)| build_sarif_run(&tool, &tool_records, workspace, &metadata))
        .collect::<Vec<_>>();
    if runs.is_empty() {
        runs.push(empty_sarif_run(&metadata, scan_run_id));
    }
    let mut properties = json!({ "kuzushiExport": metadata });
    if let Some(spend) = benchmark_spend {
        properties["kuzushiBenchmark"] = benchmark_spend_value(spend);
    }
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
        "properties": properties,
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

fn empty_sarif_run(
    metadata: &serde_json::Value,
    scan_run_id: Option<&str>,
) -> serde_json::Value {
    let driver = if scan_run_id.is_some() {
        "kuzushi:sast-scan"
    } else {
        "Kuzushi"
    };
    let mut properties = json!({ "kuzushiExport": metadata });
    if let Some(run_id) = scan_run_id {
        properties["kuzushiScanRunId"] = json!(run_id);
    }
    json!({
        "tool": { "driver": {
            "name": driver,
            "informationUri": KUZUSHI_INFORMATION_URI,
            "rules": [],
        }},
        "results": [],
        "properties": properties,
    })
}

fn benchmark_spend_value(spend: &SarifBenchmarkSpend) -> serde_json::Value {
    let mut aggregate = json!({
        "runId": spend.run_id,
        "totalCostUsd": spend.total_cost_usd,
        "source": "canonical-run-summary",
        "models": spend.models,
        "llmCallCount": spend.llm_call_count,
        "llmAuditComplete": spend.llm_audit_complete,
    });
    if let Some(config_hash) = spend.config_hash.as_ref() {
        aggregate["configHash"] = json!(config_hash);
    }
    json!({
        "schemaVersion": 2,
        "aggregateSpend": aggregate,
    })
}

fn group_findings_by_tool(
    records: &[WorkspaceFindingExportRecord],
) -> BTreeMap<String, Vec<&WorkspaceFindingExportRecord>> {
    let mut grouped: BTreeMap<String, Vec<&WorkspaceFindingExportRecord>> = BTreeMap::new();
    for record in records {
        grouped.entry(record.tool.clone()).or_default().push(record);
    }
    grouped
}

fn build_sarif_run(
    tool: &str,
    records: &[&WorkspaceFindingExportRecord],
    workspace: &WorkspaceTarget,
    metadata: &serde_json::Value,
) -> serde_json::Value {
    let rules = sarif_rules(records);
    let results = records
        .iter()
        .map(|record| sarif_result(record))
        .collect::<Vec<_>>();
    json!({
        "tool": {
            "driver": {
                "name": tool,
                "informationUri": KUZUSHI_INFORMATION_URI,
                "rules": rules,
            }
        },
        "originalUriBaseIds": {
            "WORKSPACE_ROOT": {
                "uri": format!("file://{}/", workspace.root().display()),
            }
        },
        "results": results,
        "properties": {
            "kuzushiExport": metadata,
        },
    })
}

fn sarif_rules(records: &[&WorkspaceFindingExportRecord]) -> Vec<serde_json::Value> {
    let mut rules: BTreeMap<&str, &WorkspaceFindingExportRecord> = BTreeMap::new();
    for record in records {
        rules.entry(record.rule_id.as_str()).or_insert(record);
    }
    rules
        .values()
        .map(|record| sarif_rule(record))
        .collect()
}

fn sarif_rule(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let mut rule = json!({
        "id": record.rule_id,
        "name": record.rule_id,
        "shortDescription": { "text": record.title },
        "fullDescription": { "text": record.message },
        "defaultConfiguration": { "level": sarif_level(&record.severity) },
    });
    if let Some(cwe) = record.cwe.as_ref() {
        rule["properties"] = json!({ "tags": ["security", cwe] });
    }
    rule
}

fn sarif_result(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let mut result = json!({
        "ruleId": record.rule_id,
        "level": sarif_level(&record.severity),
        "message": { "text": record.message },
        "fingerprints": { "kuzushi/v1": record.fingerprint },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": record.location.file,
                    "uriBaseId": "WORKSPACE_ROOT",
                },
                "region": sarif_region(record),
            }
        }],
        "rank": sarif_rank(&record.proof_confidence),
        "properties": sarif_properties(record),
    });
    // Both rule-based suppressions and human dismissals contribute an entry.
    // An empty vec leaves the array absent (SARIF treats absent as
    // "unsuppressed", an empty array as "checked, none found"), so we never
    // assert a suppression check we did not perform.
    let suppressions = sarif_suppressions(record);
    if !suppressions.is_empty() {
        result["suppressions"] = json!(suppressions);
    }
    result
}

/// Standard SARIF `result.suppressions[]`. A finding is emitted (never dropped)
/// with one entry per suppression cause: a rule-based suppression
/// (`record.suppressed`) and/or a human dismissal (`record.dismissal`, already
/// gated on author == Human upstream). Machine auto-triage never populates
/// `dismissal`, so it never asserts a human accepted the risk.
fn sarif_suppressions(record: &WorkspaceFindingExportRecord) -> Vec<serde_json::Value> {
    let mut suppressions = Vec::new();
    if record.suppressed {
        suppressions.push(json!({ "kind": "external", "status": "accepted" }));
    }
    if let Some(dismissal) = record.dismissal.as_ref() {
        suppressions.push(json!({
            "kind": "external",
            "status": "accepted",
            "justification": format!("{}: {}", dismissal.reason, dismissal.note),
            "properties": {
                "kuzushiDismissReason": dismissal.reason,
                "kuzushiDismissedBy": dismissal.actor,
                "kuzushiDismissedAt": dismissal.at,
                "kuzushiNote": dismissal.note,
                "kuzushiTriageState": record.triage_state,
            },
        }));
    }
    suppressions
}

/// SARIF `rank` (0.0–100.0, higher = more significant) derived from the coarse
/// proof/confidence band so downstream SARIF tools can sort by verification
/// confidence, not just severity.
fn sarif_rank(proof_confidence: &str) -> f64 {
    match proof_confidence {
        "confirmed" => 90.0,
        "likely" => 60.0,
        "dismissed" => 0.0,
        _ => 30.0,
    }
}

fn sarif_region(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let mut region = json!({ "startLine": record.location.start_line.max(1) });
    if let Some(end_line) = record.location.end_line {
        region["endLine"] = json!(end_line.max(record.location.start_line));
    }
    region
}

fn sarif_properties(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let mut properties = sarif_core_properties(record);
    merge_sarif_properties(&mut properties, sarif_evidence_properties(record));
    merge_sarif_properties(&mut properties, sarif_proof_properties(record));
    merge_sarif_properties(&mut properties, sarif_provenance_properties(record));
    properties
}

fn sarif_core_properties(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let mut properties = json!({
        "kuzushiAlias": record.alias,
        "kuzushiIdentityId": record.identity_id,
        "kuzushiKind": record.kind,
        "kuzushiConfidence": record.confidence,
        "kuzushiPriority": record.priority,
        "kuzushiLifecycleStatus": record.lifecycle_status,
        "kuzushiReviewDecision": record.review_decision,
        "kuzushiReviewDecisionConflict": record.review_decision_conflict,
        "kuzushiReviewDecisionReason": record.review_decision_reason,
        "kuzushiReviewDecisionAuthor": record.review_decision_author,
        "kuzushiTriageVerdict": record.triage_verdict,
        "kuzushiSuppressed": record.suppressed,
        "kuzushiSnoozedUntil": record.snoozed_until,
    });
    if let Some(cwe) = record.cwe.as_ref() {
        properties["kuzushiCwe"] = json!(cwe);
    }
    properties
}

fn sarif_evidence_properties(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    json!({
        "kuzushiEvidenceState": record.evidence.state,
        "kuzushiObservedEvidencePresent": record.evidence.observed_evidence_present,
        "kuzushiObservedEvidenceCount": record.evidence.observed_count,
        "kuzushiObservedCodeEvidenceCount": record.evidence.observed_code_count,
        "kuzushiObservedCaptureEvidenceCount": record.evidence.observed_capture_count,
        "kuzushiObservedOtherEvidenceCount": record.evidence.observed_other_count,
        "kuzushiModelGeneratedReasoningPresent": record.evidence.model_generated_reasoning_present,
        "kuzushiModelGeneratedReasoningCount": record.evidence.model_generated_reasoning_count,
        "kuzushiDerivedSourcePresent": record.evidence.derived_source_present,
        "kuzushiEvidenceSourceCount": record.evidence.source_count,
        "kuzushiRawHttpBlobPresent": record.evidence.raw_http_blob_present,
        "kuzushiStaticProofRecorded": record.analysis.static_proof_recorded,
        "kuzushiAutomatedReasoningPresent": record.analysis.automated_reasoning_present,
        "kuzushiHumanReviewPresent": record.analysis.human_review_present,
        "kuzushiImportedReviewPresent": record.analysis.imported_review_present,
    })
}

fn sarif_proof_properties(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    json!({
        "kuzushiStaticProofState": record.static_proof_state,
        "kuzushiStaticProofLabel": record.static_proof_label,
        "kuzushiProofConfidence": record.proof_confidence,
        "kuzushiVerification": record.verification.label,
        "kuzushiVerificationVerdict": record.verification.verdict,
        "kuzushiVerificationProofLevel": record.verification.proof_level,
        "kuzushiVerificationBackend": record.verification.backend,
        "kuzushiVerificationLanguage": record.verification.language,
    })
}

fn sarif_provenance_properties(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    json!({
        "kuzushiVulnSource": record.vuln_source,
        "kuzushiSourceSignature": record.source_signature,
        "kuzushiCorroborationCount": record.corroboration_count,
        "kuzushiRunId": record.run_id,
        "kuzushiRunStatus": record.provenance.run_status,
        "kuzushiVersion": record.provenance.kuzushi_version,
        "kuzushiModel": record.provenance.model,
        "kuzushiRuntimePlatform": record.provenance.runtime_platform,
    })
}

fn merge_sarif_properties(target: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) {
        target.extend(extra.clone());
    }
}

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" | "unknown" => "note",
        _ => "note",
    }
}
