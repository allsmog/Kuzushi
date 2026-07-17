use super::{InvocationId, KwpError, RunId};
use std::path::Path;

mod durable;
mod memory;

use durable::{DurableCostReservation, DurableCostStore};
use memory::{MemoryCostLedgerLease, MemoryCostReservation};

/// A run-cost authority. Target-qualified leases are durable; the unqualified
/// variant exists only as a compatibility shim for the dormant public broker.
#[derive(Clone)]
pub(super) struct RunCostLedgerLease {
    backend: CostLedgerBackend,
}

#[derive(Clone)]
enum CostLedgerBackend {
    Durable(DurableCostStore),
    Legacy(MemoryCostLedgerLease),
}

impl RunCostLedgerLease {
    pub(super) fn acquire(target: &Path, run_id: &RunId) -> Result<Self, KwpError> {
        Ok(Self {
            backend: CostLedgerBackend::Durable(DurableCostStore::open(target, run_id)?),
        })
    }

    /// Compatibility-only accounting for callers that cannot supply a target.
    /// Live worker execution must use `acquire` so run caps survive restarts.
    pub(super) fn acquire_legacy(run_id: &RunId) -> Self {
        Self {
            backend: CostLedgerBackend::Legacy(MemoryCostLedgerLease::acquire(run_id)),
        }
    }

    pub(super) fn reserve(
        &self,
        invocation_id: &InvocationId,
        invocation_limit: f64,
        run_limit: f64,
    ) -> Result<RuntimeCostReservation, KwpError> {
        validate_budget(invocation_limit)?;
        validate_budget(run_limit)?;
        let backend = match &self.backend {
            CostLedgerBackend::Durable(store) => RuntimeReservation::Durable(store.reserve(
                invocation_id,
                invocation_limit,
                run_limit,
            )?),
            CostLedgerBackend::Legacy(ledger) => RuntimeReservation::Legacy(ledger.reserve(
                invocation_id,
                invocation_limit,
                run_limit,
            )?),
        };
        Ok(RuntimeCostReservation {
            backend,
            finished: false,
        })
    }

    pub(super) fn invocation_cost(&self, invocation_id: &InvocationId) -> Result<f64, KwpError> {
        self.invocation_cost_report(invocation_id)
            .map(LedgerCostReport::observed_usd)
    }

    pub(super) fn run_cost(&self) -> Result<f64, KwpError> {
        self.run_cost_report().map(LedgerCostReport::charged_usd)
    }

    pub(super) fn invocation_cost_report(
        &self,
        invocation_id: &InvocationId,
    ) -> Result<LedgerCostReport, KwpError> {
        match &self.backend {
            CostLedgerBackend::Durable(store) => store.invocation_cost_report(invocation_id),
            CostLedgerBackend::Legacy(ledger) => ledger.invocation_cost_report(invocation_id),
        }
    }

    pub(super) fn run_cost_report(&self) -> Result<LedgerCostReport, KwpError> {
        match &self.backend {
            CostLedgerBackend::Durable(store) => store.run_cost_report(),
            CostLedgerBackend::Legacy(ledger) => ledger.run_cost_report(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct LedgerCostReport {
    observed_usd: f64,
    unresolved_reserved_usd: f64,
    charged_usd: f64,
}

impl LedgerCostReport {
    fn checked(observed_usd: f64, unresolved_reserved_usd: f64) -> Result<Self, KwpError> {
        validate_cost(observed_usd)?;
        validate_cost(unresolved_reserved_usd)?;
        let charged_usd = checked_cost_sum(observed_usd, unresolved_reserved_usd)?;
        Ok(Self {
            observed_usd,
            unresolved_reserved_usd,
            charged_usd,
        })
    }

    pub(super) fn observed_usd(self) -> f64 {
        self.observed_usd
    }

    pub(super) fn unresolved_reserved_usd(self) -> f64 {
        self.unresolved_reserved_usd
    }

    pub(super) fn charged_usd(self) -> f64 {
        self.charged_usd
    }

    pub(super) fn exact_usd(self) -> Option<f64> {
        (self.unresolved_reserved_usd == 0.0).then_some(self.observed_usd)
    }

    pub(super) fn is_complete(self) -> bool {
        self.unresolved_reserved_usd == 0.0
    }

    pub(super) fn runtime_report(self) -> Result<crate::runtime::RuntimeCostReport, KwpError> {
        let observed =
            crate::runtime::RuntimeCost::from_usd(self.observed_usd, "KWP observed runtime cost")
                .map_err(|error| KwpError::Internal(error.to_string()))?;
        Ok(if self.is_complete() {
            crate::runtime::RuntimeCostReport::known(observed)
        } else {
            crate::runtime::RuntimeCostReport::incomplete(observed)
        })
    }
}

pub(super) struct RuntimeCostReservation {
    backend: RuntimeReservation,
    finished: bool,
}

enum RuntimeReservation {
    Durable(DurableCostReservation),
    Legacy(MemoryCostReservation),
}

impl RuntimeCostReservation {
    pub(super) fn commit(mut self, actual_cost: f64) -> Result<CostCommit, KwpError> {
        // Once a provider returned, any invalid cost or persistence failure is
        // uncertain spend. Keep the durable reservation charged rather than
        // allowing Drop to forgive it.
        self.finished = true;
        validate_cost(actual_cost)?;
        let exceeded_reservation = match &self.backend {
            RuntimeReservation::Durable(reservation) => reservation.commit(actual_cost)?,
            RuntimeReservation::Legacy(reservation) => reservation.commit(actual_cost)?,
        };
        Ok(CostCommit {
            exceeded_reservation,
        })
    }

    pub(super) fn retain_unresolved(mut self) {
        // A successful provider call with no trustworthy price may already
        // have spent money. Keep the conservative reservation in the durable
        // ledger so a restart cannot forgive unknown spend.
        self.finished = true;
    }
}

impl Drop for RuntimeCostReservation {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        match &self.backend {
            RuntimeReservation::Durable(reservation) => reservation.rollback(),
            RuntimeReservation::Legacy(reservation) => reservation.rollback(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct CostCommit {
    pub(super) exceeded_reservation: bool,
}

fn validate_budget(value: f64) -> Result<(), KwpError> {
    if value.is_finite() && value >= 0.0 {
        Ok(())
    } else {
        Err(KwpError::RuntimeBudget)
    }
}

fn validate_cost(value: f64) -> Result<(), KwpError> {
    if value.is_finite() && value >= 0.0 {
        Ok(())
    } else {
        Err(KwpError::Internal(
            "runtime returned an invalid cost".to_string(),
        ))
    }
}

fn checked_cost_sum(current: f64, added: f64) -> Result<f64, KwpError> {
    let total = current + added;
    validate_cost(total)?;
    Ok(total)
}

#[cfg(test)]
mod tests;
