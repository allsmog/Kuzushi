use crate::capabilities::full_mode_multi::domain::FullModeReport;

pub fn report_to_tool_json(report: &FullModeReport) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "data": report,
        "summary": {
            "chunks": report.plan.chunks.len(),
            "files": report.plan.total_files,
            "totalTokens": report.plan.total_tokens,
            "findingsCount": report.findings.len(),
            "chunksDispatched": report.chunks_dispatched,
            "chunksFailed": report.chunks_failed,
            "costUsd": report.cost_usd,
            "dryRun": report.dry_run,
        },
    })
}
