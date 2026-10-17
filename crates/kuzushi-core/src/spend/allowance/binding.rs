use super::{AllowanceCall, AllowanceError, AllowanceReservation, InvestigationWork};
use crate::{runtime::RuntimeCostReport, spend::SpendLimiter};
use anyhow::Result;
use std::{fmt, sync::Arc};

/// Host-selected attribution for every model turn within one approved job.
/// Provider/model output never selects the investigation, revision or work kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowanceWork {
    pub investigation_id: String,
    pub revision: u32,
    pub run_id: String,
    pub work_id: String,
    pub model: String,
    pub work: InvestigationWork,
}

#[derive(Clone)]
pub struct AllowanceBinding {
    ledger: Arc<SpendLimiter>,
    work: AllowanceWork,
}

impl fmt::Debug for AllowanceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AllowanceBinding")
            .field("work", &self.work)
            .finish()
    }
}

impl AllowanceBinding {
    pub fn work(&self) -> &AllowanceWork {
        &self.work
    }

    /// Nested dispatch may reuse its parent accounting, never replace it.
    pub fn require_same_work(&self, other: &Self) -> Result<()> {
        self.require_ledger(&other.ledger)?;
        anyhow::ensure!(
            self.work == other.work,
            "cannot replace inherited investigation work"
        );
        Ok(())
    }

    pub(crate) fn require_ledger(&self, ledger: &SpendLimiter) -> Result<()> {
        let ledger_id = self.ledger.lock().ledger_id.clone();
        anyhow::ensure!(
            ledger_id == ledger.lock().ledger_id,
            "cannot replace an inherited allowance ledger"
        );
        Ok(())
    }

    pub fn new(ledger: Arc<SpendLimiter>, work: AllowanceWork) -> Result<Self> {
        let binding = Self { ledger, work };
        binding.call().validate()?;
        binding.validate_model(&binding.work.model)?;
        Ok(binding)
    }

    pub fn validate_model(&self, model: &str) -> Result<()> {
        if model != self.work.model {
            return Err(AllowanceError::ModelMismatch.into());
        }
        let snapshot = self
            .ledger
            .allowance_snapshot(&self.work.investigation_id)?;
        super::persistence::require_revision(self.work.revision, snapshot.revision)?;
        anyhow::ensure!(snapshot.model == model, AllowanceError::ModelMismatch);
        Ok(())
    }

    pub fn reserve(&self, model: &str) -> Result<AllowanceReservation> {
        anyhow::ensure!(model == self.work.model, AllowanceError::ModelMismatch);
        self.ledger.reserve_provider_call(&self.call())
    }

    /// Check before nonbillable preparation. Reservation remains atomic at
    /// the provider boundary, including when another worker consumes capacity.
    pub fn require_available_call(&self) -> Result<()> {
        self.validate_model(&self.work.model)?;
        self.ledger
            .allowance_snapshot(&self.work.investigation_id)?
            .require_call_capacity(self.work.work)
    }

    pub fn settle(&self, reservation: AllowanceReservation, cost: RuntimeCostReport) -> Result<()> {
        self.ledger.settle_provider_call(reservation, cost)
    }

    fn call(&self) -> AllowanceCall {
        AllowanceCall {
            investigation_id: self.work.investigation_id.clone(),
            expected_revision: self.work.revision,
            request_id: uuid::Uuid::new_v4().to_string(),
            run_id: self.work.run_id.clone(),
            work_id: self.work.work_id.clone(),
            model: self.work.model.clone(),
            work: self.work.work,
        }
    }
}
