use crate::run_lifecycle::{read_run_items, ProjectionHealth, RunItemV1};
use crate::runtime::{RuntimeCost, RuntimeCostReport};
use anyhow::Result;
use std::path::Path;

pub fn lifecycle_cost_report(target: impl AsRef<Path>, run_id: &str) -> Result<RuntimeCostReport> {
    let Some(read) = read_run_items(target, run_id)? else {
        return Ok(RuntimeCostReport::UNAVAILABLE);
    };
    if let ProjectionHealth::Degraded { reason, .. } = read.health {
        anyhow::bail!("invalid lifecycle cost stream for run {run_id}: {reason}");
    }
    model_call_cost_report(read.items.iter().map(|envelope| &envelope.item))
}

pub fn reconcile_terminal_cost_reports(
    reported: RuntimeCostReport,
    observed: RuntimeCostReport,
    context: &str,
) -> Result<RuntimeCostReport> {
    if reported.is_unavailable() {
        return Ok(observed);
    }
    if observed.is_unavailable() {
        return Ok(reported);
    }
    anyhow::ensure!(
        terminal_costs_match(reported.observed_usd(), observed.observed_usd()),
        "{context} reported cost ${:.12} conflicts with lifecycle cost ${:.12}",
        reported.observed_usd(),
        observed.observed_usd()
    );
    Ok(if reported.is_complete() {
        reported
    } else {
        observed
    })
}

pub fn terminal_model_call_cost_report(item: &RunItemV1) -> Option<RuntimeCostReport> {
    match item {
        RunItemV1::ModelCallFinished { cost, .. } => Some(*cost),
        _ => None,
    }
}

fn model_call_cost_report<'a>(
    items: impl IntoIterator<Item = &'a RunItemV1>,
) -> Result<RuntimeCostReport> {
    let mut total = RuntimeCostReport::known(RuntimeCost::ZERO);
    let mut saw_model_call = false;
    for cost in items
        .into_iter()
        .filter_map(terminal_model_call_cost_report)
    {
        saw_model_call = true;
        total = total.checked_add(cost, "lifecycle model-call cost sum")?;
    }
    Ok(if saw_model_call {
        total
    } else {
        RuntimeCostReport::UNAVAILABLE
    })
}

fn terminal_costs_match(left: f64, right: f64) -> bool {
    let scale = left.abs().max(right.abs()).max(1.0);
    (left - right).abs() <= f64::EPSILON * scale * 8.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_lifecycle::{ModelUsage, RunItemStatus, SafeText};

    fn model_finished(cost: RuntimeCostReport) -> RunItemV1 {
        RunItemV1::ModelCallFinished {
            provider: SafeText::operator_visible("openai"),
            model: SafeText::operator_visible("gpt-test"),
            status: RunItemStatus::Completed,
            latency_ms: 12,
            usage: ModelUsage {
                input_tokens: Some(4),
                output_tokens: Some(2),
            },
            cost,
            error_class: None,
            failure: None,
        }
    }

    #[test]
    fn only_terminal_model_calls_contribute_cost() {
        let exact = RuntimeCostReport::known(RuntimeCost::from_usd(0.25, "test").unwrap());
        assert_eq!(
            terminal_model_call_cost_report(&model_finished(exact)),
            Some(exact)
        );
        assert_eq!(
            terminal_model_call_cost_report(&RunItemV1::SafeReasoningSummary {
                text: SafeText::operator_visible("bounded summary"),
                redaction_policy_version: 1,
            }),
            None
        );
    }

    #[test]
    fn reconciliation_rejects_conflicting_available_totals() {
        let left = RuntimeCostReport::known(RuntimeCost::from_usd(0.1, "left").unwrap());
        let right = RuntimeCostReport::known(RuntimeCost::from_usd(0.2, "right").unwrap());
        assert!(reconcile_terminal_cost_reports(left, right, "test").is_err());
    }
}
