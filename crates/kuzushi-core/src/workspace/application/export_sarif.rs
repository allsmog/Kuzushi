//! M1 §1.4 — SARIF 2.1.0 export. One `runs[]` entry per `Finding.tool`,
//! severity → level map, fingerprints carried as `kuzushi/v1`. Lives in
//! its own module to keep `export_workspace_findings.rs` under the
//! 300-line per-file limit enforced by the CRAP-risk gate.

use super::export_metadata::workspace_export_metadata_value;
use super::export_projection_model::{
    WorkspaceFindingExportLocation, WorkspaceFindingExportRecord,
};
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const KUZUSHI_INFORMATION_URI: &str = "https://github.com/allsmog/Kuzushi";

pub(crate) fn findings_to_sarif(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    options: &WorkspaceExportOptions,
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
    options: &WorkspaceExportOptions,
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
        .collect::<Result<Vec<_>>>()?;
    if runs.is_empty() {
        runs.push(empty_sarif_run(&metadata, scan_run_id));
    }
    let properties = scan_export_properties(metadata, benchmark_spend, scan_run_id);
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
        "properties": properties,
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

fn scan_export_properties(
    metadata: serde_json::Value,
    spend: Option<&SarifBenchmarkSpend>,
    run_id: Option<&str>,
) -> serde_json::Value {
    let mut properties = json!({ "kuzushiExport": metadata });
    if let Some(run_id) = run_id {
        properties["kuzushiScanRunId"] = json!(run_id);
    }
    if let Some(spend) = spend {
        properties["kuzushiBenchmark"] = benchmark_spend_value(spend);
    }
    properties
}

fn empty_sarif_run(metadata: &serde_json::Value, scan_run_id: Option<&str>) -> serde_json::Value {
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
) -> Result<serde_json::Value> {
    let rules = sarif_rules(records);
    let results = records
        .iter()
        .map(|record| sarif_result(record))
        .collect::<Vec<_>>();
    Ok(json!({
        "tool": {
            "driver": {
                "name": tool,
                "informationUri": KUZUSHI_INFORMATION_URI,
                "rules": rules,
            }
        },
        "originalUriBaseIds": {
            "WORKSPACE_ROOT": {
                "uri": workspace_root_uri(workspace)?,
            }
        },
        "results": results,
        "properties": {
            "kuzushiExport": metadata,
        },
    }))
}

/// The `file:` URI every relative result location resolves against. SARIF
/// 2.1.0 §3.4.3 requires a real URI here, so the root has to be percent-encoded
/// and `/`-separated, and on Windows the drive letter belongs in the path
/// rather than the authority. `url` is the same encoder the clangd MCP client
/// already uses for its own file URIs; interpolating `Path::display()` produced
/// a valid URI only when the root happened to contain no character needing an
/// escape.
fn workspace_root_uri(workspace: &WorkspaceTarget) -> Result<String> {
    let root = workspace.root();
    url::Url::from_directory_path(root)
        .map(String::from)
        .map_err(|_| {
            anyhow::anyhow!(
                "Could not encode a file URI for the workspace root: {}",
                root.display()
            )
        })
}

fn sarif_rules(records: &[&WorkspaceFindingExportRecord]) -> Vec<serde_json::Value> {
    let mut rules: BTreeMap<&str, Vec<&WorkspaceFindingExportRecord>> = BTreeMap::new();
    for record in records {
        rules
            .entry(record.rule_id.as_str())
            .or_default()
            .push(record);
    }
    rules
        .into_iter()
        .map(|(rule_id, records)| sarif_rule(rule_id, &records))
        .collect()
}

fn sarif_rule(rule_id: &str, records: &[&WorkspaceFindingExportRecord]) -> serde_json::Value {
    let record = records
        .iter()
        .copied()
        .min_by_key(|record| {
            (
                sarif_severity_rank(&record.severity),
                record.fingerprint.as_str(),
            )
        })
        .expect("SARIF rule groups are non-empty");
    let mut tags = vec!["security".to_string()];
    tags.extend(
        records
            .iter()
            .filter_map(|record| record.cwe.as_ref())
            .cloned()
            .collect::<BTreeSet<_>>(),
    );
    let mut rule = json!({
        "id": rule_id,
        "name": rule_id,
        "shortDescription": { "text": record.title },
        "fullDescription": { "text": record.message },
        "help": {
            "text": "Inspect the result message, proof band, evidence properties, and recommended change before remediation."
        },
        "defaultConfiguration": { "level": sarif_level(&record.severity) },
        "properties": { "tags": tags },
    });
    if let Some(score) = sarif_security_severity(&record.severity) {
        rule["properties"]["security-severity"] = json!(score);
    }
    rule
}

fn sarif_result(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let mut result = json!({
        "ruleId": record.rule_id,
        "level": sarif_level(&record.severity),
        "message": { "text": record.message },
        "fingerprints": { "kuzushi/v1": record.fingerprint },
        "locations": [{ "physicalLocation": sarif_physical_location(&record.location) }],
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

fn sarif_physical_location(location: &WorkspaceFindingExportLocation) -> serde_json::Value {
    let mut physical_location = json!({
        "artifactLocation": sarif_artifact_location(&location.file),
    });
    if let Some(region) = sarif_region(location) {
        physical_location["region"] = region;
    }
    physical_location
}

/// SARIF 2.1.0 §3.4.4 forbids pairing `uriBaseId` with a `uri` that is already
/// absolute. Findings may be anchored to hierarchical URLs, opaque URI
/// identifiers, or absolute filesystem paths; all three must stay independent
/// of `WORKSPACE_ROOT`.
fn sarif_artifact_location(file: &str) -> serde_json::Value {
    if has_uri_scheme(file) {
        return json!({ "uri": file });
    }
    if let Some(uri) = absolute_file_uri(file) {
        return json!({ "uri": uri });
    }
    json!({ "uri": relative_uri_reference(file), "uriBaseId": "WORKSPACE_ROOT" })
}

/// The `file:` URI for a location the detector reported as an absolute
/// filesystem path, or `None` when the path is workspace-relative.
///
/// A `uri` carrying `uriBaseId` is resolved against that base, so binding an
/// absolute path to `WORKSPACE_ROOT` renames the finding: `C:\src\app.rs`
/// becomes `<workspace root>/C%3A%5Csrc%5Capp.rs`, a file that exists nowhere.
/// Absolute paths do reach this export — `normalize_reported_file_path` keeps a
/// model-reported path verbatim when it does not sit under the target root, as
/// happens for a vendored dependency read from a system prefix or for a macOS
/// `/private/var` path whose target was resolved as `/var`. Naming such a
/// location honestly outside the workspace beats re-anchoring it inside one.
///
/// A leading `\\` is deliberately *not* read as a UNC share. `\` is an ordinary
/// filename byte on Unix and `secret_relative_path` builds its path straight
/// from `Path::display()`, so a repository file named `\\build01\share.rs` would
/// be re-pointed at a network host that does not exist. That path keeps
/// resolving against `WORKSPACE_ROOT` with its bytes escaped, for the same
/// reason `relative_uri_reference` escapes `\` rather than splitting on it: the
/// escape is reversible, a wrong reading is not. A Windows drive prefix carries
/// no such ambiguity, which is why it does get an absolute reading here.
fn absolute_file_uri(file: &str) -> Option<String> {
    if is_windows_drive_absolute(file) {
        return Some(format!(
            "file:///{}",
            absolute_uri_path(&file.replace('\\', "/"))
        ));
    }
    file.starts_with('/')
        .then(|| format!("file://{}", absolute_uri_path(file)))
}

/// Percent-encode an already-`/`-separated absolute path. `:` stays literal
/// here, unlike in `relative_uri_reference`: it is a legal path character once
/// the reference is absolute, and keeping it preserves the conventional
/// `file:///C:/…` drive form that consumers map back to a Windows path.
fn absolute_uri_path(path: &str) -> String {
    path.bytes()
        .map(|byte| {
            if byte == b':' {
                ":".to_string()
            } else {
                encoded_path_byte(byte)
            }
        })
        .collect()
}

/// Turn a workspace-relative path into the URI reference SARIF 2.1.0 §3.4.2
/// asks for: `/` stays the separator and every other byte outside the RFC 3986
/// unreserved set is percent-encoded. A repository file named
/// `docs/My Notes.md` is otherwise emitted as a `uri` containing a space, which
/// consumers reject. Non-ASCII names encode per UTF-8 byte, so the escaped form
/// still names the same file, and `:` is escaped so a first segment like `C:`
/// cannot be misread as a scheme.
///
/// `\` is escaped rather than read as a separator. On Unix it is an ordinary
/// filename character that detectors preserve verbatim — `secret_relative_path`
/// builds its path straight from `Path::display()` — so splitting on it would
/// point a consumer at a file that does not exist. Producers that do run on
/// Windows paths (`incremental_index`, `inspect_entrypoints`) already normalize
/// to `/` where the path is produced, so nothing is lost by declining to guess
/// here. `%5C` is reversible; a wrong split is not.
fn relative_uri_reference(file: &str) -> String {
    file.bytes().map(encoded_path_byte).collect()
}

fn encoded_path_byte(byte: u8) -> String {
    if byte == b'/' || byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
        return char::from(byte).to_string();
    }
    format!("%{byte:02X}")
}

fn has_uri_scheme(file: &str) -> bool {
    if is_windows_drive_path(file) {
        return false;
    }
    let Some((scheme, _)) = file.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// A drive letter is never a URI scheme. This also accepts the drive-*relative*
/// `C:dir\file` form, which stays workspace-bound: it names a file relative to
/// that drive's working directory, so there is no absolute URI to emit for it.
fn is_windows_drive_path(file: &str) -> bool {
    is_windows_drive_absolute(file) || (has_drive_prefix(file) && file[2..].contains('\\'))
}

fn is_windows_drive_absolute(file: &str) -> bool {
    has_drive_prefix(file) && matches!(file.as_bytes()[2], b'/' | b'\\')
}

fn has_drive_prefix(file: &str) -> bool {
    let bytes = file.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// `start_line == 0` means the detector reported no line. Omitting the region
/// keeps the location at artifact granularity instead of asserting line 1.
fn sarif_region(location: &WorkspaceFindingExportLocation) -> Option<serde_json::Value> {
    if location.start_line == 0 {
        return None;
    }
    let mut region = json!({ "startLine": location.start_line });
    if let Some(end_line) = location.end_line {
        region["endLine"] = json!(end_line.max(location.start_line));
    }
    Some(region)
}

fn sarif_properties(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let mut properties = sarif_core_properties(record);
    merge_sarif_properties(&mut properties, sarif_evidence_properties(record));
    merge_sarif_properties(&mut properties, sarif_proof_properties(record));
    merge_sarif_properties(&mut properties, sarif_provenance_properties(record));
    merge_sarif_properties(&mut properties, sarif_remediation_properties(record));
    merge_sarif_properties(&mut properties, sarif_hunt_properties(record));
    properties
}

fn sarif_hunt_properties(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    properties.insert("kuzushiTriageState".to_string(), json!(record.triage_state));
    insert_optional_property(
        &mut properties,
        "kuzushiRecommendation",
        record.recommendation.as_ref(),
    );
    insert_optional_property(&mut properties, "kuzushiImpact", record.impact.as_ref());
    insert_optional_property(&mut properties, "kuzushiCategory", record.category.as_ref());
    insert_optional_property(
        &mut properties,
        "kuzushiExploitScenario",
        record.exploit_scenario.as_ref(),
    );
    if !record.preconditions.is_empty() {
        properties.insert(
            "kuzushiPreconditions".to_string(),
            json!(record.preconditions),
        );
    }
    serde_json::Value::Object(properties)
}

fn insert_optional_property<T: serde::Serialize>(
    properties: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<&T>,
) {
    if let Some(value) = value {
        properties.insert(key.to_string(), json!(value));
    }
}

fn sarif_remediation_properties(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let Some(remediation) = record.remediation.as_ref() else {
        return json!({});
    };
    json!({
        "kuzushiRemediationApplicationId": remediation.application_id,
        "kuzushiRemediationPatchRunId": remediation.patch_run_id,
        "kuzushiRemediationFindingScanId": remediation.finding_scan_id,
        "kuzushiRemediationApplicationState": remediation.application_state,
        "kuzushiRemediationEmpiricallyVerified": remediation.empirically_verified,
        "kuzushiRemediationReverifyOutcome": remediation.reverify_outcome,
        "kuzushiRemediationReverifyRunId": remediation.reverify_run_id,
        "kuzushiRemediationDiffHash": remediation.diff_hash,
        "kuzushiRemediationTouchedPaths": remediation.touched_paths,
    })
}

fn sarif_core_properties(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    let mut properties = json!({
        "kuzushiAlias": record.alias,
        "kuzushiIdentityId": record.identity_id,
        "kuzushiKind": record.kind,
        "kuzushiSeverity": record.severity,
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
        "kuzushiEvidenceConfidenceMax": record.evidence.evidence_confidence_max,
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
        "kuzushiVerificationSourceIdentity": record.verification.source_identity,
        "kuzushiVerificationReproducer": record.verification.reproducer,
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

fn sarif_security_severity(severity: &str) -> Option<&'static str> {
    match severity {
        "critical" => Some("9.1"),
        "high" => Some("8.0"),
        "medium" => Some("5.0"),
        "low" => Some("2.0"),
        "info" => Some("0.1"),
        _ => None,
    }
}

fn sarif_severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

#[cfg(test)]
#[path = "tests/export_sarif.rs"]
mod tests;
