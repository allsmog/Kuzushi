use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSummary {
    pub chunks: usize,
    pub files: usize,
    pub total_tokens: usize,
    pub usd_low: f64,
    pub usd_high: f64,
}

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
