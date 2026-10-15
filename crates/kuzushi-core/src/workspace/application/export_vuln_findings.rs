//! `vuln-findings` export renderer: the external orchestration schema
//! (`VULN-FINDINGS.json` shape) consumed by triage harnesses outside
//! kuzushi. One object per finding with plain-language fields; values the
//! producer never supplied stay honestly empty rather than being invented.

use super::export_projection_model::WorkspaceFindingExportRecord;
use anyhow::Result;
use serde_json::json;

pub(crate) fn findings_to_vuln_findings(
    records: &[WorkspaceFindingExportRecord],
) -> Result<String> {
    let findings: Vec<serde_json::Value> = records.iter().map(vuln_finding_row).collect();
    Ok(serde_json::to_string_pretty(&json!({
        "scan_completed": true,
        "vulnerabilities_found": !findings.is_empty(),
        "findings": findings,
    }))?)
}

fn vuln_finding_row(record: &WorkspaceFindingExportRecord) -> serde_json::Value {
    json!({
        "title": record.title,
        "impact": record
            .impact
            .clone()
            .or_else(|| record.review_decision_reason.clone())
            .unwrap_or_default(),
        "file": record.location.file,
        "line": record.location.start_line,
        "description": record.message,
        "exploit_scenario": record.exploit_scenario.clone().unwrap_or_default(),
        "preconditions": record.preconditions,
        "category": external_category(record),
        "severity": external_severity(&record.severity),
        "confidence": external_confidence(record),
        "recommendation": record.recommendation.clone().unwrap_or_default(),
        // Provenance extras (ignored by schema-strict consumers, invaluable
        // for backfill joins): the durable kuzushi identifiers and verdict.
        "goal_assessments": record.goal_assessments,
        "fingerprint": record.fingerprint,
        "triage_verdict": record.triage_verdict,
        "observation_gap": record.observation_gap,
        "observation_note": record.observation_note,
        "tool": record.tool,
    })
}

fn external_category(record: &WorkspaceFindingExportRecord) -> String {
    record
        .category
        .clone()
        .or_else(|| record.cwe.clone())
        .unwrap_or_else(|| record.rule_id.clone())
}

/// External schema uses HIGH/MEDIUM/LOW; kuzushi's critical folds into HIGH
/// and info/unknown fold into LOW.
fn external_severity(severity: &str) -> &'static str {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" | "high" => "HIGH",
        "medium" => "MEDIUM",
        _ => "LOW",
    }
}

/// Numeric confidence when triage recorded one; otherwise the proof band's
/// conventional midpoint.
fn external_confidence(record: &WorkspaceFindingExportRecord) -> f32 {
    if let Some(confidence) = record.confidence {
        return confidence.clamp(0.0, 1.0);
    }
    match record.proof_confidence.as_str() {
        "confirmed" => 0.9,
        "likely" => 0.6,
        "dismissed" => 0.1,
        _ => 0.3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(severity: &str) -> WorkspaceFindingExportRecord {
        WorkspaceFindingExportRecord {
            title: "Heap write via peer length".to_string(),
            severity: severity.to_string(),
            message: "unchecked length reaches memcpy".to_string(),
            impact: Some("remote attacker corrupts heap".to_string()),
            category: Some("buffer_overflow".to_string()),
            exploit_scenario: Some("send crafted extent".to_string()),
            preconditions: vec!["paired-peer".to_string()],
            recommendation: Some("cap length to buffer capacity".to_string()),
            fingerprint: "fp3_x".to_string(),
            proof_confidence: "likely".to_string(),
            ..WorkspaceFindingExportRecord::default()
        }
    }

    #[test]
    fn renders_the_external_schema_with_severity_and_confidence_mapping() {
        let body = findings_to_vuln_findings(&[record("critical")]).unwrap();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["scan_completed"], true);
        assert_eq!(value["vulnerabilities_found"], true);
        let row = &value["findings"][0];
        assert_eq!(row["severity"], "HIGH");
        let confidence = row["confidence"].as_f64().unwrap();
        assert!((confidence - 0.6).abs() < 1e-6, "{confidence}");
        assert_eq!(row["exploit_scenario"], "send crafted extent");
        assert_eq!(row["preconditions"][0], "paired-peer");
        assert_eq!(row["recommendation"], "cap length to buffer capacity");
        assert_eq!(row["fingerprint"], "fp3_x");
    }

    #[test]
    fn empty_record_set_is_an_honest_no_findings_report() {
        let body = findings_to_vuln_findings(&[]).unwrap();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["vulnerabilities_found"], false);
        assert_eq!(value["findings"].as_array().unwrap().len(), 0);
    }
}
