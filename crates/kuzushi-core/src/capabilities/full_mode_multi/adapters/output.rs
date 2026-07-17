use crate::capabilities::full_mode_multi::domain::FullModeReport;

pub fn report_to_tool_json(report: &FullModeReport) -> serde_json::Value {
    let summary = full_mode_summary_text(report);
    let data = serde_json::json!({
        "findings": report.findings,
        "plan": report.plan,
        "chunksDispatched": report.chunks_dispatched,
        "chunksFailed": report.chunks_failed,
        "failedChunkErrors": report.failed_chunk_errors,
        "costUsd": report.cost_usd,
        "observedCostUsd": report.observed_cost_usd,
        "unresolvedProviderSpend": report.unresolved_provider_spend,
        "dryRun": report.dry_run,
        "firstChunkError": report.first_chunk_error,
        "summary": full_mode_summary(report),
    });
    let mut result =
        crate::module_result::completed_output_result(summary.clone(), summary, data);
    if let Some(cost_usd) = report.cost_usd {
        result["costUsd"] = serde_json::json!(cost_usd);
    }
    result
}

fn full_mode_summary_text(report: &FullModeReport) -> String {
    format!(
        "full-mode:hunt {} {} chunk{} over {} file{}",
        if report.dry_run { "planned" } else { "completed" },
        report.plan.chunks.len(),
        if report.plan.chunks.len() == 1 { "" } else { "s" },
        report.plan.total_files,
        if report.plan.total_files == 1 { "" } else { "s" }
    )
}

fn full_mode_summary(report: &FullModeReport) -> serde_json::Value {
    serde_json::json!({
        "chunks": report.plan.chunks.len(),
        "files": report.plan.total_files,
        "totalTokens": report.plan.total_tokens,
        "findingsCount": report.findings.len(),
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
}
