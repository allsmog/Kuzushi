use crate::modules::ToolExecutionContext;
use crate::runtime::RuntimeCostReport;
use crate::spend::{Operation, SpendLimiter, SpendTicket};
use crate::structured_output::{CostedStructuredJson, StructuredOutputError};
use anyhow::{Context, Result};
use serde_json::Value;

const ESTIMATED_STAGE_DEPOSIT_USD: f64 = 1.0;

pub(super) fn staged_spend_limiter(ctx: &ToolExecutionContext<'_>) -> Result<Option<SpendLimiter>> {
    ctx.workspace
        .map(|workspace| {
            SpendLimiter::open_with_hard_ceiling(
                workspace.findings_db_path(),
                ctx.config.operator.spend_hard_ceiling_usd,
            )
        })
        .transpose()
}

pub(super) fn reserve_stage_budget(spend: Option<&SpendLimiter>) -> Result<Option<SpendTicket>> {
    match spend {
        Some(limiter) => limiter
            .deposit(Operation::ThreatModelStaged, ESTIMATED_STAGE_DEPOSIT_USD)
            .context("threat-model staged: spend deposit failed")
            .map(Some),
        None => Ok(None),
    }
}

pub(super) fn settle_stage_budget(
    spend: Option<&SpendLimiter>,
    ticket: Option<SpendTicket>,
    costed: &Result<CostedStructuredJson<Value>>,
) -> Result<()> {
    settle_gap_fill_cost(spend, ticket, stage_cost(costed)?.exact_usd())
}

fn stage_cost(costed: &Result<CostedStructuredJson<Value>>) -> Result<RuntimeCostReport> {
    match costed {
        Ok(costed) => costed.cost_report(),
        Err(error) => Ok(error
            .downcast_ref::<StructuredOutputError>()
            .map(StructuredOutputError::cost_report)
            .unwrap_or(RuntimeCostReport::INCOMPLETE_ZERO)),
    }
}

/// Only a complete cost receipt may replace a reservation. An unreported
/// failure or an incomplete subtotal retains the estimate across restart.
pub(super) fn settle_gap_fill_cost(
    spend: Option<&SpendLimiter>,
    ticket: Option<SpendTicket>,
    actual_usd: Option<f64>,
) -> Result<()> {
    if let (Some(limiter), Some(ticket), Some(actual_usd)) = (spend, ticket, actual_usd) {
        limiter.refund(ticket, actual_usd)?;
    }
    Ok(())
}

pub(super) fn is_spend_cap_exhausted(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<crate::spend::SpendError>(),
        Some(
            crate::spend::SpendError::Exceeded { .. }
                | crate::spend::SpendError::HardCeilingExceeded { .. }
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeCost;

    fn ledger() -> SpendLimiter {
        let ledger = SpendLimiter::open_in_memory().unwrap();
        ledger.set_cap(Operation::ThreatModelStaged, 1.0).unwrap();
        ledger
    }

    fn exact(dollars: f64) -> RuntimeCostReport {
        RuntimeCostReport::known(RuntimeCost::from_usd(dollars, "test cost").unwrap())
    }

    fn settle_stage(ledger: &SpendLimiter, result: Result<CostedStructuredJson<Value>>) {
        let ticket = reserve_stage_budget(Some(ledger)).unwrap();
        settle_stage_budget(Some(ledger), ticket, &result).unwrap();
    }

    #[test]
    fn failed_stage_without_receipt_keeps_its_reservation() {
        let ledger = ledger();
        settle_stage(&ledger, Err(anyhow::anyhow!("transport interrupted")));
        assert_eq!(ledger.total_spent_all().unwrap(), 1.0);
        assert!(reserve_stage_budget(Some(&ledger)).is_err());
    }

    #[test]
    fn successful_stage_with_unknown_cost_keeps_its_reservation() {
        let ledger = ledger();
        settle_stage(
            &ledger,
            Ok(CostedStructuredJson::from_cost_report(
                Value::Null,
                RuntimeCostReport::INCOMPLETE_ZERO,
            )),
        );
        assert_eq!(ledger.total_spent_all().unwrap(), 1.0);
    }

    #[test]
    fn structured_failure_settles_only_complete_cost_receipts() {
        let ledger = ledger();
        let error = StructuredOutputError::from_source_and_cost(
            anyhow::anyhow!("invalid structured result"),
            exact(0.25),
        );
        settle_stage(&ledger, Err(error.into()));
        assert_eq!(ledger.total_spent_all().unwrap(), 0.25);
    }

    #[test]
    fn incomplete_structured_failure_does_not_refund_its_subtotal() {
        let ledger = ledger();
        let error = StructuredOutputError::from_source_and_cost(
            anyhow::anyhow!("repair failed"),
            exact(0.25).mark_incomplete(),
        );
        settle_stage(&ledger, Err(error.into()));
        assert_eq!(ledger.total_spent_all().unwrap(), 1.0);
    }

    #[test]
    fn explicit_zero_is_distinct_from_unknown_cost() {
        let ledger = ledger();
        settle_stage(
            &ledger,
            Ok(CostedStructuredJson::from_cost_report(
                Value::Null,
                exact(0.0),
            )),
        );
        assert_eq!(ledger.total_spent_all().unwrap(), 0.0);
    }

    #[test]
    fn gap_fill_without_complete_receipt_keeps_its_reservation() {
        let ledger = ledger();
        let ticket = reserve_stage_budget(Some(&ledger)).unwrap();
        settle_gap_fill_cost(Some(&ledger), ticket, None).unwrap();
        assert_eq!(ledger.total_spent_all().unwrap(), 1.0);
    }
}
