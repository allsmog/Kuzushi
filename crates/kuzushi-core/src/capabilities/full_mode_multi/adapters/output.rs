use crate::capabilities::full_mode_multi::domain::FullModeReport;
use crate::findings::{Finding, Severity};
use std::collections::BTreeMap;

pub fn report_to_tool_json(report: &FullModeReport) -> serde_json::Value {
    let summary = full_mode_summary_text(report);
    let output_text = full_mode_output_text(report);
    let mut data = serde_json::json!({
        "findings": report.findings,
        "plan": report.plan,
        "chunksDispatched": report.chunks_dispatched,
        "chunksFailed": report.chunks_failed,
        "failedChunkErrors": report.failed_chunk_errors,
        "dryRun": report.dry_run,
        "firstChunkError": report.first_chunk_error,
        "summary": full_mode_summary(report),
    });
    let claim = cost_claim(report);
    for (key, value) in &claim {
        data[key] = value.clone();
    }
    let mut result = crate::module_result::completed_output_result(summary, output_text, data);
    for (key, value) in claim {
        result[key] = value;
    }
    result
}

/// Run-artifact persistence accepts exactly one cost claim
/// (`tool_run_output_cost_report`): exact `costUsd`, or
/// `observedCostUsd` + `providerSpendUnresolved` when provider spend never
/// resolved. Emitting both fails persistence and turns a completed hunt
/// into a failed run.
fn cost_claim(report: &FullModeReport) -> serde_json::Map<String, serde_json::Value> {
    let mut claim = serde_json::Map::new();
    if report.unresolved_provider_spend {
        claim.insert(
            "observedCostUsd".to_string(),
            serde_json::json!(report.observed_cost_usd),
        );
        claim.insert("providerSpendUnresolved".to_string(), serde_json::json!(true));
    } else if let Some(cost_usd) = report.cost_usd {
        claim.insert("costUsd".to_string(), serde_json::json!(cost_usd));
    }
    claim
}

fn full_mode_summary_text(report: &FullModeReport) -> String {
    let mut parts = vec![geometry_phrase(report)];
    parts.extend(findings_phrase(report));
    parts.extend(failed_chunks_phrase(report));
    parts.join(" · ")
}

fn geometry_phrase(report: &FullModeReport) -> String {
    format!(
        "full-mode:hunt {} {} chunk{} over {} file{}",
        if report.dry_run { "planned" } else { "completed" },
        report.plan.chunks.len(),
        if report.plan.chunks.len() == 1 { "" } else { "s" },
        report.plan.total_files,
        if report.plan.total_files == 1 { "" } else { "s" }
    )
}

/// A planned (dry) run has no findings truth to state.
fn findings_phrase(report: &FullModeReport) -> Option<String> {
    if report.dry_run {
        return None;
    }
    let count = report.findings.len();
    if count == 0 {
        return Some("no findings".to_string());
    }
    let noun = if count == 1 { "finding" } else { "findings" };
    Some(format!(
        "{count} {noun} ({})",
        severity_breakdown(&report.findings)
    ))
}

/// Non-zero severity buckets, highest band first: "137 critical, 343 high".
fn severity_breakdown(findings: &[Finding]) -> String {
    severity_counts(findings)
        .iter()
        .rev()
        .map(|(severity, count)| format!("{count} {}", severity.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn severity_counts(findings: &[Finding]) -> BTreeMap<Severity, usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.severity).or_insert(0) += 1;
    }
    counts
}

fn severity_counts_json(findings: &[Finding]) -> serde_json::Value {
    let buckets = severity_counts(findings)
        .iter()
        .rev()
        .map(|(severity, count)| (severity.as_str().to_string(), serde_json::json!(count)))
        .collect::<serde_json::Map<_, _>>();
    serde_json::Value::Object(buckets)
}

/// Coverage gaps are surfaced whenever non-zero — a degraded-coverage signal
/// the operator must see, never silent state.
fn failed_chunks_phrase(report: &FullModeReport) -> Option<String> {
    if report.chunks_failed == 0 {
        return None;
    }
    let plural = if report.chunks_failed == 1 { "" } else { "s" };
    Some(format!("{} chunk{plural} failed", report.chunks_failed))
}

fn full_mode_output_text(report: &FullModeReport) -> String {
    let mut lines = vec![full_mode_summary_text(report)];
    if !report.dry_run {
        lines.extend(failed_chunks_detail(report));
        append_top_findings(&mut lines, &report.findings);
    }
    lines.join("\n")
}

fn failed_chunks_detail(report: &FullModeReport) -> Option<String> {
    if report.chunks_failed == 0 {
        return None;
    }
    Some(format!(
        "  Failed chunks: {}{}",
        failed_chunk_ids(report),
        first_error_suffix(report)
    ))
}

fn failed_chunk_ids(report: &FullModeReport) -> String {
    let ids = report
        .failed_chunk_errors
        .iter()
        .map(|error| error.chunk_id.to_string())
        .collect::<Vec<_>>();
    if ids.is_empty() {
        report.chunks_failed.to_string()
    } else {
        ids.join(", ")
    }
}

fn first_error_suffix(report: &FullModeReport) -> String {
    report
        .first_chunk_error
        .as_deref()
        .and_then(|error| error.lines().next())
        .map(|line| format!(" — first error: {line}"))
        .unwrap_or_default()
}

fn append_top_findings(lines: &mut Vec<String>, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top findings:".to_string());
    lines.extend(crate::findings::presentation::top_finding_lines(
        findings, 10,
    ));
}

fn full_mode_summary(report: &FullModeReport) -> serde_json::Value {
    serde_json::json!({
        "chunks": report.plan.chunks.len(),
        "files": report.plan.total_files,
        "totalTokens": report.plan.total_tokens,
        "findingsCount": report.findings.len(),
        "severityCounts": severity_counts_json(&report.findings),
        "chunksDispatched": report.chunks_dispatched,
        "chunksFailed": report.chunks_failed,
        "failedChunkErrors": report.failed_chunk_errors,
        "costUsd": report.cost_usd,
        "observedCostUsd": report.observed_cost_usd,
        "unresolvedProviderSpend": report.unresolved_provider_spend,
        "dryRun": report.dry_run,
        "firstChunkError": report.first_chunk_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::full_mode_multi::domain::{FullModePlan, FullModeReport};

    #[test]
    fn report_output_uses_completed_envelope() {
        let report = FullModeReport {
            findings: Vec::new(),
            plan: FullModePlan {
                chunks: Vec::new(),
                total_files: 2,
                total_bytes: 128,
                total_tokens: 32,
            },
            chunks_dispatched: 0,
            chunks_failed: 0,
            failed_chunk_errors: Vec::new(),
            cost_usd: Some(0.0),
            observed_cost_usd: 0.0,
            unresolved_provider_spend: false,
            dry_run: true,
            first_chunk_error: None,
        };

        let output = report_to_tool_json(&report);

        assert_eq!(output["ok"], serde_json::json!(true));
        assert_eq!(output["status"], serde_json::json!("completed"));
        assert_eq!(
            output["summary"],
            serde_json::json!("full-mode:hunt planned 0 chunks over 2 files")
        );
        assert_eq!(output["data"]["dryRun"], serde_json::json!(true));
        assert_eq!(
            output["data"]["summary"]["totalTokens"],
            serde_json::json!(32)
        );
    }

    #[test]
    fn resolved_spend_claims_exact_cost_only_and_persists() {
        let mut report = sample_report();
        report.cost_usd = Some(1.418025);
        report.observed_cost_usd = 1.418025;
        report.unresolved_provider_spend = false;

        let output = report_to_tool_json(&report);

        assert_eq!(output["costUsd"], serde_json::json!(1.418025));
        assert_eq!(output["data"]["costUsd"], serde_json::json!(1.418025));
        assert!(output["data"].get("observedCostUsd").is_none());
        assert!(output.get("observedCostUsd").is_none());
        crate::run_artifacts::tool_run_output_cost_report(&output)
            .expect("resolved-spend hunt output must satisfy the persistence cost contract");
    }

    #[test]
    fn unresolved_spend_claims_observed_cost_and_persists() {
        let mut report = sample_report();
        report.cost_usd = None;
        report.observed_cost_usd = 0.5;
        report.unresolved_provider_spend = true;

        let output = report_to_tool_json(&report);

        assert_eq!(output["data"]["observedCostUsd"], serde_json::json!(0.5));
        assert_eq!(
            output["data"]["providerSpendUnresolved"],
            serde_json::json!(true)
        );
        assert!(output["data"].get("costUsd").is_none());
        crate::run_artifacts::tool_run_output_cost_report(&output)
            .expect("unresolved-spend hunt output must satisfy the persistence cost contract");
    }

    #[test]
    fn live_summary_states_findings_count_and_severity_breakdown() {
        let mut report = sample_report();
        report.findings = vec![
            test_finding("rule-a", crate::findings::Severity::Critical),
            test_finding("rule-b", crate::findings::Severity::High),
            test_finding("rule-c", crate::findings::Severity::High),
        ];

        let output = report_to_tool_json(&report);

        assert_eq!(
            output["summary"],
            serde_json::json!(
                "full-mode:hunt completed 0 chunks over 2 files · 3 findings (1 critical, 2 high)"
            )
        );
        assert_eq!(
            output["data"]["summary"]["severityCounts"],
            serde_json::json!({"critical": 1, "high": 2})
        );
        let text = output["output"].as_str().unwrap();
        assert!(text.contains("Top findings:"));
        assert!(text.contains("  - critical - rule-a - src/a.c:42"));
    }

    #[test]
    fn live_output_clamps_top_findings_with_remaining_count() {
        let mut report = sample_report();
        report.findings = (0..12)
            .map(|index| {
                test_finding(&format!("rule-{index}"), crate::findings::Severity::High)
            })
            .collect();

        let output = report_to_tool_json(&report);

        assert!(output["output"]
            .as_str()
            .unwrap()
            .ends_with("  ... and 2 more"));
    }

    #[test]
    fn live_summary_states_no_findings_explicitly() {
        let report = sample_report();

        let output = report_to_tool_json(&report);

        assert_eq!(
            output["summary"],
            serde_json::json!("full-mode:hunt completed 0 chunks over 2 files · no findings")
        );
        assert!(!output["output"].as_str().unwrap().contains("Top findings:"));
    }

    #[test]
    fn failed_chunks_surface_in_summary_and_output_detail() {
        let mut report = sample_report();
        report.chunks_failed = 2;
        report.failed_chunk_errors = vec![
            crate::capabilities::full_mode_multi::domain::FailedChunkError {
                chunk_id: 3,
                reason: "rate limit".to_string(),
            },
            crate::capabilities::full_mode_multi::domain::FailedChunkError {
                chunk_id: 5,
                reason: "auth".to_string(),
            },
        ];
        report.first_chunk_error = Some("provider 429\ncaused by: quota".to_string());

        let output = report_to_tool_json(&report);

        assert_eq!(
            output["summary"],
            serde_json::json!(
                "full-mode:hunt completed 0 chunks over 2 files · no findings · 2 chunks failed"
            )
        );
        assert!(output["output"]
            .as_str()
            .unwrap()
            .contains("  Failed chunks: 3, 5 — first error: provider 429"));
    }

    #[test]
    fn dry_run_summary_stays_geometry_only() {
        let mut report = sample_report();
        report.dry_run = true;
        report.findings = vec![test_finding("rule-a", crate::findings::Severity::High)];

        let output = report_to_tool_json(&report);

        assert_eq!(
            output["summary"],
            serde_json::json!("full-mode:hunt planned 0 chunks over 2 files")
        );
        assert_eq!(output["output"], output["summary"]);
    }

    fn test_finding(rule_id: &str, severity: crate::findings::Severity) -> Finding {
        Finding::new_tool(
            "full-mode",
            rule_id,
            "src/a.c",
            42,
            None,
            severity,
            "test finding",
        )
    }

    fn sample_report() -> FullModeReport {
        FullModeReport {
            findings: Vec::new(),
            plan: FullModePlan {
                chunks: Vec::new(),
                total_files: 2,
                total_bytes: 128,
                total_tokens: 32,
            },
            chunks_dispatched: 7,
            chunks_failed: 0,
            failed_chunk_errors: Vec::new(),
            cost_usd: Some(0.0),
            observed_cost_usd: 0.0,
            unresolved_provider_spend: false,
            dry_run: false,
            first_chunk_error: None,
        }
    }
}
