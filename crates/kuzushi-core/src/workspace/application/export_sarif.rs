//! M1 §1.4 — SARIF 2.1.0 export. One `runs[]` entry per `Finding.tool`,
//! severity → level map, fingerprints carried as `kuzushi/v1`. Lives in
//! its own module to keep `export_workspace_findings.rs` under the
//! 300-line per-file limit enforced by the CRAP-risk gate.

use super::*;
use crate::findings::Severity;
use std::collections::BTreeMap;

const KUZUSHI_INFORMATION_URI: &str = "https://github.com/allsmog/Kuzushi";

pub(crate) fn findings_to_sarif(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
) -> Result<String> {
    let runs = group_findings_by_tool(findings)
        .into_iter()
        .map(|(tool, tool_findings)| build_sarif_run(&tool, &tool_findings, workspace))
        .collect::<Vec<_>>();
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

fn group_findings_by_tool(findings: &[Finding]) -> BTreeMap<String, Vec<&Finding>> {
    let mut grouped: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        grouped.entry(finding.tool.clone()).or_default().push(finding);
    }
    grouped
}

fn build_sarif_run(
    tool: &str,
    findings: &[&Finding],
    workspace: &WorkspaceTarget,
) -> serde_json::Value {
    let rules = sarif_rules(findings);
    let results = findings
        .iter()
        .map(|finding| sarif_result(finding))
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
    })
}

fn sarif_rules(findings: &[&Finding]) -> Vec<serde_json::Value> {
    let mut rules: BTreeMap<&str, &Finding> = BTreeMap::new();
    for finding in findings {
        rules.entry(finding.rule_id.as_str()).or_insert(finding);
    }
    rules
        .values()
        .map(|finding| {
            json!({
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": { "text": finding.title },
                "fullDescription": { "text": finding.message },
                "defaultConfiguration": { "level": sarif_level(finding.severity) },
            })
        })
        .collect()
}

fn sarif_result(finding: &Finding) -> serde_json::Value {
    json!({
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": { "text": finding.message },
        "fingerprints": { "kuzushi/v1": finding.fingerprint },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.file_path,
                    "uriBaseId": "WORKSPACE_ROOT",
                },
                "region": sarif_region(finding),
            }
        }],
    })
}

fn sarif_region(finding: &Finding) -> serde_json::Value {
    let mut region = json!({ "startLine": finding.start_line.max(1) });
    if let Some(end_line) = finding.end_line {
        region["endLine"] = json!(end_line.max(finding.start_line));
    }
    region
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info | Severity::Unknown => "note",
    }
}
