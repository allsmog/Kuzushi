use super::{read_run_artifact_text, RunArtifactRead, RunTraceStep};
use crate::runtime::{RuntimeCost, RuntimeCostReport};
use anyhow::{Context, Result};
use std::path::Path;

/// Derive the checked provider-cost state from this run's bounded canonical
/// trace. Only terminal model-call rows participate; completion and preflight
/// rows are excluded so callers cannot double count terminalization metadata.
pub fn trace_cost_report(target: impl AsRef<Path>, run_id: &str) -> Result<RuntimeCostReport> {
    let target = target.as_ref();
    let body = match read_run_artifact_text(target, run_id, "trace.jsonl") {
        RunArtifactRead::Ready { value, .. } => value,
        RunArtifactRead::Missing { .. } => return Ok(RuntimeCostReport::UNAVAILABLE),
        other => {
            return Err(anyhow::anyhow!(
                "could not read bounded canonical trace for run {run_id}: {}",
                other.display_path()
            ));
        }
    };
    model_call_cost_report_from_jsonl(&body)
        .map_err(|error| anyhow::anyhow!("invalid runtime cost trace for run {run_id}: {error:#}"))
}

/// Reconcile a terminal producer's reported total with the canonical trace.
///
/// Either source may be unavailable for compatibility, but two available
/// sources must agree. An exact report wins over an incomplete report with the
/// same observed subtotal.
pub fn reconcile_terminal_cost_reports(
    reported: RuntimeCostReport,
    traced: RuntimeCostReport,
    context: &str,
) -> Result<RuntimeCostReport> {
    if reported.is_unavailable() {
        return Ok(traced);
    }
    if traced.is_unavailable() {
        return Ok(reported);
    }
    anyhow::ensure!(
        terminal_costs_match(reported.observed_usd(), traced.observed_usd()),
        "{context} reported cost ${:.12} conflicts with canonical trace cost ${:.12}",
        reported.observed_usd(),
        traced.observed_usd()
    );
    Ok(if reported.is_complete() {
        reported
    } else {
        traced
    })
}

fn terminal_costs_match(left: f64, right: f64) -> bool {
    let scale = left.abs().max(right.abs()).max(1.0);
    (left - right).abs() <= f64::EPSILON * scale * 8.0
}

fn model_call_cost_report_from_jsonl(body: &str) -> Result<RuntimeCostReport> {
    let mut total = RuntimeCostReport::known(RuntimeCost::ZERO);
    let mut saw_terminal_model_call = false;
    for (index, line) in body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let step: RunTraceStep = serde_json::from_str(line)
            .with_context(|| format!("trace line {} is not a valid trace step", index + 1))?;
        let Some(call_cost) = terminal_model_call_cost_report(&step)? else {
            continue;
        };
        saw_terminal_model_call = true;
        total = total.checked_add(call_cost, "trace model-call cost sum")?;
    }
    if !saw_terminal_model_call {
        return Ok(RuntimeCostReport::UNAVAILABLE);
    }
    Ok(total)
}

/// Classify one trace row using the same terminal model-call contract as the
/// bounded run-level parser. Non-call, completion, and tool-loop preflight rows
/// return `None`; a terminal call returns exact cost or incomplete observed
/// zero when the provider omitted usage.
pub fn terminal_model_call_cost_report(step: &RunTraceStep) -> Result<Option<RuntimeCostReport>> {
    super::write_run_artifact_json::validate_trace_step_cost(step)?;
    if !is_terminal_model_call(step) {
        return Ok(None);
    }
    Ok(Some(trace_step_cost_report(step)?))
}

fn is_terminal_model_call(step: &RunTraceStep) -> bool {
    match step.call_attempted {
        Some(attempted) => attempted,
        None => legacy_terminal_model_call(step),
    }
}

fn trace_step_cost_report(step: &RunTraceStep) -> Result<RuntimeCostReport> {
    if let Some(cost_usd) = step.cost_usd {
        return Ok(RuntimeCostReport::known(RuntimeCost::from_usd(
            cost_usd,
            "trace model-call cost",
        )?));
    }
    if let Some(cost_usd) = step.observed_cost_usd {
        return Ok(RuntimeCostReport::incomplete(RuntimeCost::from_usd(
            cost_usd,
            "trace observed model-call cost",
        )?));
    }
    Ok(RuntimeCostReport::INCOMPLETE_ZERO)
}

fn legacy_terminal_model_call(step: &RunTraceStep) -> bool {
    step.latency_ms.is_some()
        && step.model.is_some()
        && step.provider.is_some()
        && step.prompt_hash.is_some()
        && !is_tool_loop_preflight(step)
}

fn is_tool_loop_preflight(step: &RunTraceStep) -> bool {
    step.verb.as_deref() == Some("next-step") && step.label.starts_with("tool-loop preflight")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_cost_report_distinguishes_unavailable_exact_and_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(trace_cost_report(tmp.path(), "missing")
            .unwrap()
            .is_unavailable());

        append_terminal(tmp.path(), "exact", 1, Some(0.1));
        append_terminal(tmp.path(), "exact", 2, Some(0.2));
        let exact = trace_cost_report(tmp.path(), "exact").unwrap();
        assert!((exact.exact_usd().unwrap() - 0.3).abs() < 1e-12);

        append_terminal(tmp.path(), "incomplete", 1, Some(0.1));
        append_terminal(tmp.path(), "incomplete", 2, None);
        let incomplete = trace_cost_report(tmp.path(), "incomplete").unwrap();
        assert_eq!(incomplete.observed_usd_if_available(), Some(0.1));
        assert!(!incomplete.is_complete());
        assert!(!incomplete.is_unavailable());
    }

    #[test]
    fn trace_cost_report_rejects_invalid_and_overflowing_cost_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        append_terminal(tmp.path(), "overflow", 1, Some(f64::MAX));
        append_terminal(tmp.path(), "overflow", 2, Some(f64::MAX));
        assert!(trace_cost_report(tmp.path(), "overflow").is_err());

        let path = super::super::run_artifact_path(tmp.path(), "invalid", "trace.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            r#"{"n":1,"kind":"reasoning","label":"model","latency_ms":1,"cost_usd":-1.0,"model":"m","provider":"p","prompt_hash":"h"}
"#,
        )
        .unwrap();
        assert!(trace_cost_report(tmp.path(), "invalid").is_err());
    }

    #[test]
    fn terminal_call_classifier_excludes_non_calls_and_preflight_rows() {
        let ordinary = RunTraceStep::new(1, "tool", "complete");
        let preflight = RunTraceStep::new(2, "reasoning", "tool-loop preflight")
            .with_latency_ms(Some(1))
            .with_model_metadata("m", "p", "h")
            .with_verb("next-step");
        let exact = terminal_step(3, Some(0.25));
        let incomplete = terminal_step(4, None);

        assert!(terminal_model_call_cost_report(&ordinary)
            .unwrap()
            .is_none());
        assert!(terminal_model_call_cost_report(&preflight)
            .unwrap()
            .is_none());
        assert_eq!(
            terminal_model_call_cost_report(&exact)
                .unwrap()
                .unwrap()
                .exact_usd(),
            Some(0.25)
        );
        assert_eq!(
            terminal_model_call_cost_report(&incomplete)
                .unwrap()
                .unwrap()
                .observed_usd_if_available(),
            Some(0.0)
        );
    }

    #[test]
    fn explicit_attempt_state_overrides_legacy_metadata_shape() {
        let pre_call = terminal_step(1, None).with_call_attempted(false);
        let attempted =
            RunTraceStep::new(2, "refused", "provider disconnected").with_call_attempted(true);

        assert!(terminal_model_call_cost_report(&pre_call)
            .unwrap()
            .is_none());
        assert_eq!(
            terminal_model_call_cost_report(&attempted)
                .unwrap()
                .unwrap(),
            RuntimeCostReport::INCOMPLETE_ZERO
        );
    }

    #[test]
    fn explicit_unattempted_call_rejects_contradictory_spend() {
        let exact = terminal_step(1, Some(0.1)).with_call_attempted(false);
        let observed = RunTraceStep::new(2, "refused", "pre-call")
            .with_call_attempted(false)
            .with_cost_report(RuntimeCostReport::incomplete(
                RuntimeCost::from_usd(0.1, "test observed cost").unwrap(),
            ));

        assert!(terminal_model_call_cost_report(&exact).is_err());
        assert!(terminal_model_call_cost_report(&observed).is_err());
    }

    #[test]
    fn trace_preserves_incomplete_observed_subtotal() {
        let observed = RuntimeCost::from_usd(0.25, "test observed cost").unwrap();
        let step = RunTraceStep::new(1, "reasoning", "model")
            .with_call_attempted(true)
            .with_cost_report(RuntimeCostReport::incomplete(observed));

        assert_eq!(
            terminal_model_call_cost_report(&step).unwrap().unwrap(),
            RuntimeCostReport::incomplete(observed)
        );
    }

    #[test]
    fn terminal_cost_reconciliation_falls_back_and_rejects_conflicts() {
        let exact = RuntimeCostReport::known(RuntimeCost::from_usd(0.2, "test cost").unwrap());

        assert_eq!(
            reconcile_terminal_cost_reports(
                RuntimeCostReport::UNAVAILABLE,
                exact,
                "test terminal",
            )
            .unwrap(),
            exact
        );
        assert_eq!(
            reconcile_terminal_cost_reports(
                exact,
                RuntimeCostReport::UNAVAILABLE,
                "test terminal",
            )
            .unwrap(),
            exact
        );
        let other = RuntimeCostReport::known(RuntimeCost::from_usd(0.3, "test cost").unwrap());
        assert!(reconcile_terminal_cost_reports(exact, other, "test terminal").is_err());
    }

    fn append_terminal(target: &Path, run_id: &str, n: usize, cost_usd: Option<f64>) {
        let step = terminal_step(n, cost_usd);
        super::super::append_run_trace_step(target, run_id, &step).unwrap();
    }

    fn terminal_step(n: usize, cost_usd: Option<f64>) -> RunTraceStep {
        RunTraceStep::new(n, "reasoning", "model")
            .with_latency_ms(Some(1))
            .with_model_metadata("m", "p", "h")
            .with_cost_usd(cost_usd)
    }
}
