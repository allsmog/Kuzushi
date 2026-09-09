use super::*;
use kuzushi_core::capabilities::trace_expansion::{
    load_latest_trace_expansion, TraceExpansionSource, TraceStep,
};

impl ShellApp {
    /// Reopen complete outcomes from canonical results, with legacy step history.
    pub(crate) fn hydrate_trace_expansion_from_store(&mut self, fingerprint: &str) {
        let Some(root) = self.target().map(std::path::Path::to_path_buf) else {
            return;
        };
        match load_trace_snapshot(&root, fingerprint) {
            Ok(Some(snapshot)) => self.accept_trace_history(snapshot),
            Ok(None) => {}
            Err(_) => {
                self.domain_mut().set_trace_expansion(None);
                self.set_error_notice("trace", "Saved Trace evidence could not be verified. Inspect the run artifacts before relying on the recorded path.");
            }
        }
    }

    fn accept_trace_history(&mut self, snapshot: TraceExpansionSnapshot) {
        let existing = self
            .domain()
            .trace_expansion_for_finding(&snapshot.finding_fingerprint);
        // A just-completed live outcome may not yet have its durable result.
        if snapshot.last_outcome.is_none() && existing.is_some() {
            return;
        }
        self.domain_mut().set_trace_expansion(Some(snapshot));
    }
}

fn load_trace_snapshot(
    root: &std::path::Path,
    fingerprint: &str,
) -> anyhow::Result<Option<TraceExpansionSnapshot>> {
    let workspace = kuzushi_core::WorkspaceTarget::new(root)?;
    let store = kuzushi_core::static_evidence::StaticEvidenceStore::open(&workspace)?;
    let steps = kuzushi_core::capabilities::trace_expansion::list_operator_trace_steps(
        &store,
        fingerprint,
    )?;
    let latest = load_latest_trace_expansion(root, fingerprint)?;
    if steps.is_empty() && latest.is_none() {
        return Ok(None);
    }
    let mut snapshot = TraceExpansionSnapshot {
        finding_fingerprint: fingerprint.to_string(),
        steps: steps.into_iter().map(trace_step).collect(),
        open_questions: Vec::new(),
        evidence_deltas: Vec::new(),
        last_outcome: None,
    };
    if let Some(latest) = latest {
        snapshot.last_outcome = Some(format!(
            "Last expansion · {} new steps · run {} · {}",
            latest.result.steps.len(),
            latest.run_id,
            source_label(latest.source)
        ));
        for step in latest.result.steps.into_iter().map(trace_step) {
            if !snapshot.steps.contains(&step) {
                snapshot.steps.push(step);
            }
        }
        snapshot.open_questions = latest.result.open_questions;
        snapshot.evidence_deltas = latest.result.evidence_deltas;
    }
    Ok(Some(snapshot))
}

fn source_label(source: TraceExpansionSource) -> &'static str {
    match source {
        TraceExpansionSource::Current => "last expansion source unchanged",
        TraceExpansionSource::Changed => "source changed since last expansion",
        TraceExpansionSource::Unrecorded => "last expansion source identity not recorded",
        TraceExpansionSource::Unverified => "last expansion source could not be verified",
    }
}

pub(super) fn cache_trace_expansion_snapshot(
    app: &mut ShellApp,
    tool_name: &str,
    data: &serde_json::Value,
) -> bool {
    if tool_name != "trace:expand" {
        return false;
    }
    let Some(fingerprint) = data_string(data, "findingFingerprint") else {
        return true;
    };
    let steps = data
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|step| serde_json::from_value::<TraceStep>(step.clone()).ok())
        .map(trace_step)
        .collect::<Vec<_>>();
    let last_outcome = Some(format!("Last expansion result · {} new steps", steps.len()));
    app.domain_mut()
        .set_trace_expansion(Some(TraceExpansionSnapshot {
            finding_fingerprint: fingerprint,
            steps,
            open_questions: limited_string_array(data, "openQuestions", usize::MAX),
            evidence_deltas: limited_string_array(data, "evidenceDeltas", usize::MAX),
            last_outcome,
        }));
    true
}

fn trace_step(step: TraceStep) -> TraceExpansionStep {
    TraceExpansionStep {
        symbol: step.symbol,
        file: step.file_path,
        line: step.line,
        annotation: step.annotation,
    }
}

#[cfg(test)]
mod tests;
