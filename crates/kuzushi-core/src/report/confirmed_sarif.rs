//! `report:sarif` — SARIF 2.1.0 export of review-confirmed findings.
//!
//! Exports only findings whose LATEST review decision confirms them
//! (`Confirmed` or `ToFix`). Shared dispatch reads the canonical effective
//! review across observations; a later rejection reverses confirmation. Rules
//! are derived from CWE ids; the run carries the workspace trend object
//! (FP rate, cost per confirmed finding) as properties, so a CI consumer
//! sees effectiveness alongside the findings. Deterministic; no model calls.

use crate::capabilities::campaign::trend::{
    latest_confirmed_finding_ids, trend_json, trend_metrics_for_findings, trend_metrics_with_spend,
    workspace_campaign_spend_report,
};
use crate::findings::{extract_cwe, Finding, ReviewDecisionRecord};
use crate::workspace::InvestigationReportReceipt;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
mod metadata;

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const DRIVER_NAME: &str = "kuzushi";
const DRIVER_INFORMATION_URI: &str = "https://github.com/allsmog/Kuzushi";
const DEFAULT_OUTPUT: &str = "reports/confirmed-findings.sarif";

/// What one export covers: workspace history, or a single study whose
/// investigation receipt travels with the results.
pub struct ConfirmedSarifSelection<'a> {
    pub findings: &'a [Finding],
    pub records: &'a [ReviewDecisionRecord],
    pub investigation: Option<&'a InvestigationReportReceipt>,
}

pub fn export_confirmed_sarif(
    root: &Path,
    input: &Value,
    selection: &ConfirmedSarifSelection<'_>,
) -> Result<Value> {
    let receipt = selection
        .investigation
        .map(serde_json::to_value)
        .transpose()?;
    export_selection(
        root,
        input,
        selection.findings,
        selection.records,
        receipt,
        &[],
    )
}

pub(crate) fn export_confirmed_sarif_document(
    root: &Path,
    input: &Value,
    findings: &[Finding],
    records: &[ReviewDecisionRecord],
    investigation: Option<&crate::workspace::InvestigationReportDocument>,
    metadata: &[crate::workspace::WorkspaceFindingExportRecord],
) -> Result<Value> {
    let receipt = investigation.map(serde_json::to_value).transpose()?;
    export_selection(root, input, findings, records, receipt, metadata)
}

fn export_selection(
    root: &Path,
    input: &Value,
    findings: &[Finding],
    records: &[ReviewDecisionRecord],
    receipt: Option<Value>,
    metadata: &[crate::workspace::WorkspaceFindingExportRecord],
) -> Result<Value> {
    let confirmed = confirmed_findings_with_metadata(findings, records, metadata);
    let spend = workspace_campaign_spend_report(root);
    let metrics = if metadata.is_empty() {
        trend_metrics_with_spend(records, spend)
    } else {
        trend_metrics_for_findings(findings, records, spend)
    };
    let trend = trend_json(&metrics);
    let mut document = sarif_document(&confirmed, trend.clone());
    metadata::attach_export_metadata(
        &mut document,
        &confirmed,
        records,
        metadata,
        receipt.is_some(),
    )?;
    attach_investigation(&mut document, receipt)?;
    let path = write_sarif(root, input, &document)?;
    Ok(export_result(&path, &confirmed, trend))
}

/// Same location `workspace:export-findings` uses for SARIF receipts.
fn attach_investigation(document: &mut Value, investigation: Option<Value>) -> Result<()> {
    let Some(receipt) = investigation else {
        return Ok(());
    };
    document["runs"][0]["properties"]["kuzushiExport"]["investigation"] = receipt;
    Ok(())
}

/// The public compatibility export selects the latest decision by finding id.
/// Shared dispatch uses canonical review metadata across observations. Undecided,
/// rejected, review-suppressed, deferred, and accepted-risk findings are excluded.
/// this export is the "hand a CI gate only what a review stood behind"
/// surface, unlike `workspace:export-findings`.
/// Rule suppression remains independent and is disclosed in result properties.
fn confirmed_findings(findings: &[Finding], records: &[ReviewDecisionRecord]) -> Vec<Finding> {
    let confirmed_ids = latest_confirmed_finding_ids(records);
    findings
        .iter()
        .filter(|finding| finding.id.is_some_and(|id| confirmed_ids.contains(&id)))
        .cloned()
        .collect()
}

fn confirmed_findings_with_metadata(
    findings: &[Finding],
    records: &[ReviewDecisionRecord],
    metadata: &[crate::workspace::WorkspaceFindingExportRecord],
) -> Vec<Finding> {
    if metadata.is_empty() {
        return confirmed_findings(findings, records);
    }
    let confirmed = metadata
        .iter()
        .filter(|record| matches!(record.review_decision.as_str(), "confirmed" | "to_fix"))
        .map(|record| record.fingerprint.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    findings
        .iter()
        .filter(|finding| confirmed.contains(finding.fingerprint.as_str()))
        .cloned()
        .collect()
}

fn sarif_document(findings: &[Finding], trend: Value) -> Value {
    json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": { "driver": {
                "name": DRIVER_NAME,
                "informationUri": DRIVER_INFORMATION_URI,
                "rules": sarif_rules(findings),
            }},
            "results": findings.iter().map(sarif_result).collect::<Vec<_>>(),
            "properties": { "kuzushiTrend": trend },
        }],
    })
}

/// One rule per distinct rule id, CWE-first: findings with an extractable
/// CWE share `CWE-<n>` rules; findings without one keep their scanner rule
/// id, so every result's `ruleId` resolves to a declared rule.
fn sarif_rules(findings: &[Finding]) -> Vec<Value> {
    let mut rules: BTreeMap<String, &Finding> = BTreeMap::new();
    for finding in findings {
        rules.entry(sarif_rule_id(finding)).or_insert(finding);
    }
    rules
        .iter()
        .map(|(id, finding)| sarif_rule(id, finding))
        .collect()
}

fn sarif_rule_id(finding: &Finding) -> String {
    extract_cwe(&finding.rule_id, &finding.title, &finding.message)
        .unwrap_or_else(|| finding.rule_id.clone())
}

fn sarif_rule(id: &str, finding: &Finding) -> Value {
    json!({
        "id": id,
        "name": id,
        "shortDescription": { "text": finding.title },
        "defaultConfiguration": { "level": sarif_level(finding) },
        "properties": { "tags": ["security"] },
    })
}

fn sarif_result(finding: &Finding) -> Value {
    json!({
        "ruleId": sarif_rule_id(finding),
        "level": sarif_level(finding),
        "message": { "text": finding.message },
        "fingerprints": { "kuzushi/v1": finding.fingerprint },
        "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": finding.file_path },
            "region": sarif_region(finding),
        }}],
        "properties": {
            "kuzushiSeverity": finding.severity.as_str(),
            "kuzushiTool": finding.tool,
            "kuzushiTitle": finding.title,
            "kuzushiObservationGap": finding.observation_gap,
            "kuzushiObservationNote": crate::findings::observation_gap_note(finding),
        },
    })
}

fn sarif_region(finding: &Finding) -> Value {
    let start_line = finding.start_line.max(1);
    let mut region = json!({ "startLine": start_line });
    if let Some(end_line) = finding.end_line {
        region["endLine"] = json!(end_line.max(start_line));
    }
    region
}

fn sarif_level(finding: &Finding) -> &'static str {
    match finding.severity.as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// Resolve `output` (relative paths land under the workspace root; default
/// `.kuzushi/v3/reports/confirmed-findings.sarif`) and write the document.
fn write_sarif(root: &Path, input: &Value, document: &Value) -> Result<PathBuf> {
    let path = output_path(root, input)?;
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Could not create {}", parent.display()))?;
    let body = serde_json::to_string_pretty(document).context("Could not serialize SARIF")?;
    crate::fs_atomic::write_atomic(&path, &body)
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn output_path(root: &Path, input: &Value) -> Result<PathBuf> {
    let requested = input
        .get("output")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    crate::workspace::resolve_report_output_path(root, requested.map(Path::new), DEFAULT_OUTPUT)
        .context("report:sarif output must resolve inside the workspace root")
}

fn export_result(path: &Path, confirmed: &[Finding], trend: Value) -> Value {
    let output = format!(
        "report:sarif exported {} confirmed finding(s) to {}",
        confirmed.len(),
        path.display()
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "path": path.display().to_string(),
            "resultCount": confirmed.len(),
            "trend": trend,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        FindingStore, ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor,
    };

    fn decision(verdict: ReviewDecisionVerdict) -> ReviewDecision {
        ReviewDecision {
            verdict,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "reviewed".to_string(),
            dismiss_reason: None,
            actor: None,
        }
    }

    fn insert(store: &FindingStore, rule: &str, severity: Severity, message: &str) -> i64 {
        let finding = Finding::new_semgrep(rule, "src/app.c", 12, Some(14), severity, message);
        store.insert_finding("run-sarif", &finding).unwrap()
    }

    fn export(root: &Path, store: &FindingStore, input: Value) -> Value {
        let findings = store.list_all_findings().unwrap();
        let records = store.list_review_decisions_for_findings(&findings).unwrap();
        export_confirmed_sarif(root, &input, &history(&findings, &records)).unwrap()
    }

    fn history<'a>(
        findings: &'a [Finding],
        records: &'a [ReviewDecisionRecord],
    ) -> ConfirmedSarifSelection<'a> {
        ConfirmedSarifSelection {
            findings,
            records,
            investigation: None,
        }
    }

    fn written_document(result: &Value) -> Value {
        let path = result["data"]["path"].as_str().unwrap();
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn exports_only_findings_whose_latest_decision_confirms_them() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-sarif", tmp.path(), "running")
            .unwrap();
        let confirmed = insert(
            &store,
            "cwe-787.stack-write",
            Severity::Critical,
            "OOB write",
        );
        let reversed = insert(&store, "cwe-89.sqli", Severity::High, "SQL injection");
        let to_fix = insert(&store, "custom.rule", Severity::Medium, "hardening gap");
        insert(&store, "cwe-321.key", Severity::Low, "undecided finding");
        store
            .append_user_review_decision(confirmed, &decision(ReviewDecisionVerdict::Confirmed))
            .unwrap();
        // Reversal: confirm then reject — the rejection wins, so it is excluded.
        store
            .append_user_review_decision(reversed, &decision(ReviewDecisionVerdict::Confirmed))
            .unwrap();
        store
            .append_user_review_decision(
                reversed,
                &decision(ReviewDecisionVerdict::RejectedFalsePositive),
            )
            .unwrap();
        store
            .append_user_review_decision(to_fix, &decision(ReviewDecisionVerdict::ToFix))
            .unwrap();

        let result = export(tmp.path(), &store, json!({}));
        let document = written_document(&result);

        assert_eq!(result["data"]["resultCount"], 2);
        assert_eq!(document["$schema"], SARIF_SCHEMA);
        assert_eq!(document["version"], SARIF_VERSION);
        let run = &document["runs"][0];
        let rule_ids = run["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| rule["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(rule_ids, vec!["CWE-787", "custom.rule"]);
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        let by_rule = |id: &str| {
            results
                .iter()
                .find(|result| result["ruleId"] == id)
                .unwrap()
                .clone()
        };
        let critical = by_rule("CWE-787");
        assert_eq!(critical["level"], "error");
        assert_eq!(
            critical["locations"][0]["physicalLocation"]["region"]["startLine"],
            12
        );
        assert_eq!(by_rule("custom.rule")["level"], "warning");
        // Trend rides run properties: 3 decided, 1 rejected FP.
        let trend = &run["properties"]["kuzushiTrend"];
        assert_eq!(trend["decidedFindings"], 3);
        assert_eq!(trend["confirmedFindings"], 2);
        assert!((trend["fpRate"].as_f64().unwrap() - 1.0 / 3.0).abs() < 1e-9);
    }

    /// Hostile finding text (model output / scanned repo content) must not
    /// break SARIF JSON structure, forge extra results, or leak past the
    /// serialization boundary unescaped.
    #[test]
    fn hostile_finding_text_cannot_break_sarif_structure_or_forge_results() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-sarif", tmp.path(), "running")
            .unwrap();
        let hostile_message =
            "\"}]}],\"runs\":[{\"results\":[{\"ruleId\":\"forged\"}\n\u{1b}]52;c;x\u{7}";
        let id = insert(&store, "custom.hostile", Severity::High, hostile_message);
        store
            .append_user_review_decision(id, &decision(ReviewDecisionVerdict::Confirmed))
            .unwrap();

        let result = export(tmp.path(), &store, json!({}));
        // written_document round-trips through serde: if the hostile text had
        // broken structure this parse would fail or shape would change.
        let document = written_document(&result);

        let runs = document["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1, "no forged runs");
        let results = runs[0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1, "no forged results");
        assert_eq!(results[0]["ruleId"], "custom.hostile");
        assert_eq!(
            results[0]["message"]["text"].as_str().unwrap(),
            hostile_message,
            "text survives round-trip as data, not structure"
        );
    }

    #[test]
    fn sarif_output_outside_the_workspace_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open_in_memory().unwrap();
        let findings = store.list_all_findings().unwrap();
        let records = store.list_review_decisions_for_findings(&findings).unwrap();

        for output in ["../escape.sarif", "/tmp/outside-report.sarif"] {
            let error = export_confirmed_sarif(
                tmp.path(),
                &json!({ "output": output }),
                &history(&findings, &records),
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("inside the workspace root"),
                "{output}: {error}"
            );
        }
    }

    #[test]
    fn empty_store_emits_valid_empty_sarif() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open_in_memory().unwrap();

        let result = export(tmp.path(), &store, json!({}));
        let document = written_document(&result);

        assert_eq!(result["data"]["resultCount"], 0);
        assert_eq!(document["version"], SARIF_VERSION);
        let run = &document["runs"][0];
        assert_eq!(run["tool"]["driver"]["rules"], json!([]));
        assert_eq!(run["results"], json!([]));
        assert_eq!(run["properties"]["kuzushiTrend"]["decidedFindings"], 0);
        assert_eq!(run["properties"]["kuzushiTrend"]["fpRate"], Value::Null);
    }

    #[test]
    fn findings_without_decisions_export_no_results_and_honor_output_option() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-sarif", tmp.path(), "running")
            .unwrap();
        insert(
            &store,
            "cwe-787.stack-write",
            Severity::Critical,
            "OOB write",
        );

        let result = export(tmp.path(), &store, json!({ "output": "out/custom.sarif" }));

        assert_eq!(result["data"]["resultCount"], 0);
        let expected = std::fs::canonicalize(tmp.path().join("out/custom.sarif")).unwrap();
        assert_eq!(
            result["data"]["path"].as_str().unwrap(),
            expected.display().to_string()
        );
        let document = written_document(&result);
        assert_eq!(document["runs"][0]["results"], json!([]));
    }
}
