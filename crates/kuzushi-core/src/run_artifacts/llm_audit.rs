use super::{run_dir, RunLlmCallAudit, RunTraceStep};
use std::fs;
use std::path::Path;

pub(crate) fn load_run_llm_audit(target: &Path, run_id: &str) -> Vec<RunLlmCallAudit> {
    fs::read_to_string(run_dir(target, run_id).join("trace.jsonl"))
        .map(|body| audit_calls_from_trace_jsonl(&body))
        .unwrap_or_default()
}

fn audit_calls_from_trace_jsonl(body: &str) -> Vec<RunLlmCallAudit> {
    body.lines()
        .filter_map(|line| serde_json::from_str::<RunTraceStep>(line).ok())
        .filter_map(audit_call_from_trace_step)
        .collect()
}

fn audit_call_from_trace_step(step: RunTraceStep) -> Option<RunLlmCallAudit> {
    Some(RunLlmCallAudit {
        n: step.n,
        kind: step.kind,
        verb: step.verb,
        model: step.model?,
        provider: step.provider?,
        prompt_hash: step.prompt_hash?,
        latency_ms: step.latency_ms,
        cost_usd: step.cost_usd,
    })
}
