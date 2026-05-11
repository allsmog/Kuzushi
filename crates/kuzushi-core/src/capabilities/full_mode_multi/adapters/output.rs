use crate::capabilities::full_mode_multi::domain::FullModeReport;

pub fn report_to_tool_json(report: &FullModeReport) -> serde_json::Value {
    let mut summary = serde_json::json!({
        "chunks": report.plan.chunks.len(),
        "files": report.plan.total_files,
        "totalTokens": report.plan.total_tokens,
        "findingsCount": report.findings.len(),
        "chunksDispatched": report.chunks_dispatched,
        "chunksFailed": report.chunks_failed,
        "costUsd": report.cost_usd,
        "dryRun": report.dry_run,
    });
    // Surface the captured chunk error in the summary too so an operator
    // glancing at the trailer of the tool result doesn't have to dig into
    // `data.firstChunkError` to know why the scan dispatched 0 chunks.
    if let (Some(err), Some(map)) = (
        report.first_chunk_error.as_deref(),
        summary.as_object_mut(),
    ) {
        map.insert(
            "firstChunkError".to_string(),
            serde_json::Value::String(err.to_string()),
        );
    }
    serde_json::json!({
        "ok": true,
        "data": report,
        "summary": summary,
    })
}
