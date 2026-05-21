use super::{run_dir, RunLlmCallAudit, RunTraceStep};
use std::fs;
use std::path::Path;

pub(crate) struct RunTraceAudit {
    pub(crate) llm_calls: Vec<RunLlmCallAudit>,
    pub(crate) malformed_lines: usize,
}

pub(crate) fn load_run_trace_audit(target: &Path, run_id: &str) -> RunTraceAudit {
    fs::read_to_string(run_dir(target, run_id).join("trace.jsonl"))
        .map(|body| trace_audit_from_jsonl(&body))
        .unwrap_or_else(|_| RunTraceAudit {
            llm_calls: Vec::new(),
            malformed_lines: 0,
        })
}

fn trace_audit_from_jsonl(body: &str) -> RunTraceAudit {
    let mut llm_calls = Vec::new();
    let mut malformed_lines = 0usize;
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<RunTraceStep>(line) {
            Ok(step) => {
                if let Some(call) = audit_call_from_trace_step(step) {
                    llm_calls.push(call);
                }
            }
            Err(_) => malformed_lines += 1,
        }
    }
    RunTraceAudit {
        llm_calls,
        malformed_lines,
    }
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
