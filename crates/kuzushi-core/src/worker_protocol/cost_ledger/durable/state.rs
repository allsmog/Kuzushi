use super::super::{checked_cost_sum, InvocationId, KwpError, LedgerCostReport, RunId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

const LEDGER_SCHEMA_VERSION: u32 = 1;
const MAX_LEDGER_ENTRIES: usize = 4096;
const MAX_INVOCATION_ID_BYTES: usize = 1024;

#[derive(Clone)]
pub(super) struct LedgerIdentity {
    target_sha256: String,
    pub(super) run_id: String,
}

impl LedgerIdentity {
    pub(super) fn new(target: &Path, run_id: &RunId) -> Self {
        Self {
            target_sha256: super::target_binding(target),
            run_id: run_id.0.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DurableLedgerState {
    schema_version: u32,
    target_sha256: String,
    run_id: String,
    committed_usd: f64,
    unattributed_committed_usd: f64,
    invocation_committed_usd: BTreeMap<String, f64>,
    reservations: BTreeMap<String, DurableReservationRecord>,
}

impl DurableLedgerState {
    pub(super) fn new(identity: &LedgerIdentity, recovered_cost: f64) -> Self {
        Self {
            schema_version: LEDGER_SCHEMA_VERSION,
            target_sha256: identity.target_sha256.clone(),
            run_id: identity.run_id.clone(),
            committed_usd: recovered_cost,
            unattributed_committed_usd: recovered_cost,
            invocation_committed_usd: BTreeMap::new(),
            reservations: BTreeMap::new(),
        }
    }

    pub(super) fn reserve(
        &mut self,
        invocation_id: &InvocationId,
        invocation_limit: f64,
        run_limit: f64,
    ) -> Result<(String, f64), KwpError> {
        let invocation_available = invocation_limit - self.invocation_total(&invocation_id.0)?;
        let run_available = run_limit - self.run_total()?;
        let amount = invocation_available.min(run_available);
        if amount <= 0.0 {
            return Err(KwpError::RuntimeBudget);
        }
        let reservation_id = uuid::Uuid::new_v4().to_string();
        self.reservations.insert(
            reservation_id.clone(),
            DurableReservationRecord {
                invocation_id: invocation_id.0.clone(),
                reserved_usd: amount,
            },
        );
        Ok((reservation_id, amount))
    }

    pub(super) fn commit(
        &mut self,
        reservation_id: &str,
        actual_cost: f64,
        reserved_limit: f64,
    ) -> Result<bool, KwpError> {
        let reservation = self
            .reservations
            .get(reservation_id)
            .cloned()
            .ok_or_else(missing_reservation)?;
        let invocation_total = checked_cost_sum(
            self.invocation_committed(&reservation.invocation_id),
            actual_cost,
        )?;
        let committed_total = checked_cost_sum(self.committed_usd, actual_cost)?;
        self.reservations.remove(reservation_id);
        self.invocation_committed_usd
            .insert(reservation.invocation_id, invocation_total);
        self.committed_usd = committed_total;
        Ok(actual_cost > reserved_limit)
    }

    pub(super) fn rollback(&mut self, reservation_id: &str) {
        self.reservations.remove(reservation_id);
    }

    pub(super) fn reconcile_canonical_cost(
        &mut self,
        canonical_cost: f64,
    ) -> Result<bool, KwpError> {
        validate_finite_cost(canonical_cost, "run summary cost")?;
        let charged_total = self.run_total()?;
        if canonical_cost <= charged_total || costs_match(canonical_cost, charged_total) {
            return Ok(false);
        }
        // `run.json.costUsd` is a total, not an additional child charge. Raise
        // the floor only by the difference from committed plus pending spend.
        let additional = canonical_cost - charged_total;
        self.unattributed_committed_usd =
            checked_cost_sum(self.unattributed_committed_usd, additional)?;
        self.committed_usd = checked_cost_sum(self.committed_usd, additional)?;
        Ok(true)
    }

    pub(super) fn invocation_committed(&self, invocation_id: &str) -> f64 {
        self.invocation_committed_usd
            .get(invocation_id)
            .copied()
            .unwrap_or(0.0)
    }

    pub(super) fn run_total(&self) -> Result<f64, KwpError> {
        self.run_cost_report().map(LedgerCostReport::charged_usd)
    }

    pub(super) fn invocation_cost_report(
        &self,
        invocation_id: &str,
    ) -> Result<LedgerCostReport, KwpError> {
        let unresolved = self
            .reservations
            .values()
            .filter(|reservation| reservation.invocation_id == invocation_id)
            .try_fold(0.0, |total, reservation| {
                checked_cost_sum(total, reservation.reserved_usd)
            })?;
        LedgerCostReport::checked(self.invocation_committed(invocation_id), unresolved)
    }

    pub(super) fn run_cost_report(&self) -> Result<LedgerCostReport, KwpError> {
        let unresolved = self
            .reservations
            .values()
            .try_fold(0.0, |total, reservation| {
                checked_cost_sum(total, reservation.reserved_usd)
            })?;
        LedgerCostReport::checked(self.committed_usd, unresolved)
    }

    pub(super) fn validate(&self, identity: &LedgerIdentity) -> Result<(), KwpError> {
        validate_header(self, identity)?;
        validate_entry_counts(self)?;
        validate_ledger_costs(self)?;
        for (invocation_id, cost) in &self.invocation_committed_usd {
            validate_invocation_id(invocation_id)?;
            validate_finite_cost(*cost, "invocation committed cost")?;
        }
        for (reservation_id, reservation) in &self.reservations {
            validate_reservation(reservation_id, reservation)?;
        }
        self.run_cost_report().map(|_| ())
    }

    fn invocation_total(&self, invocation_id: &str) -> Result<f64, KwpError> {
        self.reservations
            .values()
            .filter(|reservation| reservation.invocation_id == invocation_id)
            .try_fold(
                self.invocation_committed(invocation_id),
                |total, reservation| checked_cost_sum(total, reservation.reserved_usd),
            )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableReservationRecord {
    invocation_id: String,
    reserved_usd: f64,
}

fn validate_header(ledger: &DurableLedgerState, identity: &LedgerIdentity) -> Result<(), KwpError> {
    if ledger.schema_version != LEDGER_SCHEMA_VERSION {
        return Err(super::invalid_ledger("unsupported schema version"));
    }
    if ledger.target_sha256 != identity.target_sha256 {
        return Err(super::invalid_ledger("target binding mismatch"));
    }
    if ledger.run_id != identity.run_id {
        return Err(super::invalid_ledger("run binding mismatch"));
    }
    Ok(())
}

fn validate_entry_counts(ledger: &DurableLedgerState) -> Result<(), KwpError> {
    if ledger.invocation_committed_usd.len() > MAX_LEDGER_ENTRIES
        || ledger.reservations.len() > MAX_LEDGER_ENTRIES
    {
        Err(super::invalid_ledger("too many entries"))
    } else {
        Ok(())
    }
}

fn validate_ledger_costs(ledger: &DurableLedgerState) -> Result<(), KwpError> {
    validate_finite_cost(ledger.committed_usd, "committed cost")?;
    validate_finite_cost(
        ledger.unattributed_committed_usd,
        "unattributed committed cost",
    )?;
    let attributed = ledger
        .invocation_committed_usd
        .values()
        .try_fold(ledger.unattributed_committed_usd, |total, cost| {
            checked_cost_sum(total, *cost)
        })?;
    if costs_match(attributed, ledger.committed_usd) {
        Ok(())
    } else {
        Err(super::invalid_ledger("committed totals do not reconcile"))
    }
}

fn validate_reservation(
    reservation_id: &str,
    reservation: &DurableReservationRecord,
) -> Result<(), KwpError> {
    uuid::Uuid::parse_str(reservation_id)
        .map_err(|_| super::invalid_ledger("reservation ID is invalid"))?;
    validate_invocation_id(&reservation.invocation_id)?;
    validate_finite_cost(reservation.reserved_usd, "reserved cost")?;
    if reservation.reserved_usd > 0.0 {
        Ok(())
    } else {
        Err(super::invalid_ledger("reserved cost must be positive"))
    }
}

pub(super) fn validate_invocation_id(invocation_id: &str) -> Result<(), KwpError> {
    if invocation_id.is_empty()
        || invocation_id.len() > MAX_INVOCATION_ID_BYTES
        || invocation_id.chars().any(char::is_control)
    {
        Err(super::invalid_ledger("invocation ID is invalid"))
    } else {
        Ok(())
    }
}

pub(super) fn validate_finite_cost(cost: f64, label: &str) -> Result<(), KwpError> {
    if cost.is_finite() && cost >= 0.0 {
        Ok(())
    } else {
        Err(super::invalid_ledger(&format!("{label} is invalid")))
    }
}

fn costs_match(left: f64, right: f64) -> bool {
    let tolerance = 1e-9_f64.max(left.abs().max(right.abs()) * 1e-9);
    (left - right).abs() <= tolerance
}

fn missing_reservation() -> KwpError {
    KwpError::Internal("runtime cost reservation is missing".to_string())
}
