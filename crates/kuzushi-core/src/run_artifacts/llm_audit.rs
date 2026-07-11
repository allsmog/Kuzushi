use super::{read_run_artifact_text, RunArtifactRead, RunLlmCallAudit, RunTraceStep};
use crate::artifact_contract::{canonical_run_artifact_spec, CanonicalRunArtifactSpec};
use serde_json::Value;
use std::path::Path;

pub(crate) struct RunTraceAudit {
    pub(crate) llm_calls: Vec<RunLlmCallAudit>,
    pub(crate) malformed_lines: usize,
}

pub(crate) fn load_run_trace_audit(target: &Path, run_id: &str) -> RunTraceAudit {
    match read_run_artifact_text(target, run_id, run_trace_audit_spec().leaf) {
        RunArtifactRead::Ready { value, .. } => trace_audit_from_jsonl(&value),
        RunArtifactRead::Missing { .. } => empty_trace_audit(),
        RunArtifactRead::NonFile { .. }
        | RunArtifactRead::Unsafe { .. }
        | RunArtifactRead::Unreadable { .. } => invalid_trace_audit(),
    }
}

fn run_trace_audit_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("trace.jsonl")
        .expect("runtime trace audit artifact must be in shared spec")
}

fn empty_trace_audit() -> RunTraceAudit {
    RunTraceAudit {
        llm_calls: Vec::new(),
        malformed_lines: 0,
    }
}

fn invalid_trace_audit() -> RunTraceAudit {
    RunTraceAudit {
        llm_calls: Vec::new(),
        malformed_lines: 1,
    }
}

fn trace_audit_from_jsonl(body: &str) -> RunTraceAudit {
    let mut llm_calls = Vec::new();
    let mut malformed_lines = 0usize;
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        match trace_step_from_line(line) {
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

fn trace_step_from_line(line: &str) -> Result<RunTraceStep, serde_json::Error> {
    let value = serde_json::from_str::<Value>(line)?;
    if !value.is_object() {
        return serde_json::from_value(value);
    }
    serde_json::from_value(value)
}

fn audit_call_from_trace_step(step: RunTraceStep) -> Option<RunLlmCallAudit> {
    if !is_llm_audit_step(&step) {
        return None;
    }
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

fn is_llm_audit_step(step: &RunTraceStep) -> bool {
    step.kind == "reasoning" || step.latency_ms.is_some() || step.cost_usd.is_some()
}
