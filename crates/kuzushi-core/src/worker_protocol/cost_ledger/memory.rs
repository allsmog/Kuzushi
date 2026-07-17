use super::{checked_cost_sum, InvocationId, KwpError, LedgerCostReport, RunId};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};

static LEGACY_COST_LEDGERS: OnceLock<Mutex<MemoryLedgerRegistry>> = OnceLock::new();
const LEGACY_TARGET_QUALIFIER: &str = "<legacy-unqualified-worker-target>";

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct MemoryLedgerKey {
    target: PathBuf,
    run_id: RunId,
}

#[derive(Clone)]
pub(super) struct MemoryCostLedgerLease {
    key: MemoryLedgerKey,
    ledger: Arc<Mutex<MemoryCostLedger>>,
}

impl MemoryCostLedgerLease {
    pub(super) fn acquire(run_id: &RunId) -> Self {
        let key = MemoryLedgerKey {
            target: PathBuf::from(LEGACY_TARGET_QUALIFIER),
            run_id: run_id.clone(),
        };
        let mut registry = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ledger = registry.acquire(&key);
        Self { key, ledger }
    }

    pub(super) fn reserve(
        &self,
        invocation_id: &InvocationId,
        invocation_limit: f64,
        run_limit: f64,
    ) -> Result<MemoryCostReservation, KwpError> {
        let mut ledger = self.ledger.lock().map_err(|_| poisoned_ledger())?;
        let reservation = ledger.reserve(invocation_id, invocation_limit, run_limit)?;
        Ok(MemoryCostReservation {
            key: self.key.clone(),
            ledger: Arc::clone(&self.ledger),
            reservation_id: reservation.id,
            limit: reservation.amount,
        })
    }

    pub(super) fn invocation_cost_report(
        &self,
        invocation_id: &InvocationId,
    ) -> Result<LedgerCostReport, KwpError> {
        let ledger = self.ledger.lock().map_err(|_| poisoned_ledger())?;
        ledger.invocation_cost_report(invocation_id)
    }

    pub(super) fn run_cost_report(&self) -> Result<LedgerCostReport, KwpError> {
        let ledger = self.ledger.lock().map_err(|_| poisoned_ledger())?;
        ledger.run_cost_report()
    }
}

impl Drop for MemoryCostLedgerLease {
    fn drop(&mut self) {
        release(&self.key, &self.ledger);
    }
}

pub(super) struct MemoryCostReservation {
    key: MemoryLedgerKey,
    ledger: Arc<Mutex<MemoryCostLedger>>,
    reservation_id: u64,
    limit: f64,
}

impl MemoryCostReservation {
    pub(super) fn commit(&self, actual_cost: f64) -> Result<bool, KwpError> {
        let mut ledger = self.ledger.lock().map_err(|_| poisoned_ledger())?;
        ledger.commit(self.reservation_id, actual_cost, self.limit)
    }

    pub(super) fn rollback(&self) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.rollback(self.reservation_id);
        }
    }
}

impl Drop for MemoryCostReservation {
    fn drop(&mut self) {
        release(&self.key, &self.ledger);
    }
}

#[derive(Default)]
struct MemoryLedgerRegistry {
    ledgers: HashMap<MemoryLedgerKey, Weak<Mutex<MemoryCostLedger>>>,
}

impl MemoryLedgerRegistry {
    fn acquire(&mut self, key: &MemoryLedgerKey) -> Arc<Mutex<MemoryCostLedger>> {
        self.remove_abandoned();
        if let Some(ledger) = self.ledgers.get(key).and_then(Weak::upgrade) {
            return ledger;
        }
        let ledger = Arc::new(Mutex::new(MemoryCostLedger::default()));
        self.ledgers.insert(key.clone(), Arc::downgrade(&ledger));
        ledger
    }

    fn release(&mut self, key: &MemoryLedgerKey, ledger: &Arc<Mutex<MemoryCostLedger>>) {
        if Arc::strong_count(ledger) == 1
            && self
                .ledgers
                .get(key)
                .is_some_and(|registered| registered.ptr_eq(&Arc::downgrade(ledger)))
        {
            self.ledgers.remove(key);
        }
        self.remove_abandoned();
    }

    fn remove_abandoned(&mut self) {
        self.ledgers.retain(|_, ledger| ledger.strong_count() > 0);
    }
}

#[derive(Default)]
struct MemoryCostLedger {
    run_committed: f64,
    invocation_committed: BTreeMap<InvocationId, f64>,
    reservations: BTreeMap<u64, ReservationState>,
    next_reservation_id: u64,
}

impl MemoryCostLedger {
    fn reserve(
        &mut self,
        invocation_id: &InvocationId,
        invocation_limit: f64,
        run_limit: f64,
    ) -> Result<ReservationState, KwpError> {
        let amount = available_reservation(self, invocation_id, invocation_limit, run_limit)?;
        if amount <= 0.0 {
            return Err(KwpError::RuntimeBudget);
        }
        let reservation = ReservationState {
            id: self.next_reservation_id,
            invocation_id: invocation_id.clone(),
            amount,
        };
        self.next_reservation_id = self
            .next_reservation_id
            .checked_add(1)
            .ok_or_else(|| KwpError::Internal("runtime reservation IDs exhausted".to_string()))?;
        self.reservations
            .insert(reservation.id, reservation.clone());
        Ok(reservation)
    }

    fn commit(
        &mut self,
        reservation_id: u64,
        actual_cost: f64,
        reserved_limit: f64,
    ) -> Result<bool, KwpError> {
        let reservation = self
            .reservations
            .get(&reservation_id)
            .cloned()
            .ok_or_else(|| KwpError::Internal("runtime cost reservation is missing".to_string()))?;
        let invocation_total = checked_cost_sum(
            self.invocation_committed(&reservation.invocation_id)?,
            actual_cost,
        )?;
        let run_total = checked_cost_sum(self.run_committed, actual_cost)?;
        self.reservations.remove(&reservation_id);
        self.invocation_committed
            .insert(reservation.invocation_id, invocation_total);
        self.run_committed = run_total;
        Ok(actual_cost > reserved_limit)
    }

    fn rollback(&mut self, reservation_id: u64) {
        self.reservations.remove(&reservation_id);
    }

    fn invocation_total(&self, invocation_id: &InvocationId) -> Result<f64, KwpError> {
        self.invocation_cost_report(invocation_id)
            .map(LedgerCostReport::charged_usd)
    }

    fn invocation_cost_report(
        &self,
        invocation_id: &InvocationId,
    ) -> Result<LedgerCostReport, KwpError> {
        let unresolved = self
            .reservations
            .values()
            .filter(|reservation| &reservation.invocation_id == invocation_id)
            .try_fold(0.0, |total, reservation| {
                checked_cost_sum(total, reservation.amount)
            })?;
        LedgerCostReport::checked(self.invocation_committed(invocation_id)?, unresolved)
    }

    fn invocation_committed(&self, invocation_id: &InvocationId) -> Result<f64, KwpError> {
        let committed = self
            .invocation_committed
            .get(invocation_id)
            .copied()
            .unwrap_or(0.0);
        checked_cost_sum(0.0, committed)
    }

    fn run_total(&self) -> Result<f64, KwpError> {
        self.run_cost_report().map(LedgerCostReport::charged_usd)
    }

    fn run_cost_report(&self) -> Result<LedgerCostReport, KwpError> {
        let unresolved = self
            .reservations
            .values()
            .try_fold(0.0, |total, reservation| {
                checked_cost_sum(total, reservation.amount)
            })?;
        LedgerCostReport::checked(self.run_committed, unresolved)
    }
}

#[derive(Clone)]
struct ReservationState {
    id: u64,
    invocation_id: InvocationId,
    amount: f64,
}

fn available_reservation(
    ledger: &MemoryCostLedger,
    invocation_id: &InvocationId,
    invocation_limit: f64,
    run_limit: f64,
) -> Result<f64, KwpError> {
    let invocation_available = invocation_limit - ledger.invocation_total(invocation_id)?;
    let run_available = run_limit - ledger.run_total()?;
    let available = invocation_available.min(run_available);
    if available.is_finite() {
        Ok(available)
    } else {
        Err(KwpError::Internal(
            "runtime available-cost calculation overflowed".to_string(),
        ))
    }
}

fn registry() -> &'static Mutex<MemoryLedgerRegistry> {
    LEGACY_COST_LEDGERS.get_or_init(|| Mutex::new(MemoryLedgerRegistry::default()))
}

fn release(key: &MemoryLedgerKey, ledger: &Arc<Mutex<MemoryCostLedger>>) {
    let mut registry = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.release(key, ledger);
}

fn poisoned_ledger() -> KwpError {
    KwpError::Internal("KWP legacy run-cost ledger was poisoned".to_string())
}

#[cfg(test)]
pub(super) fn registry_contains(run_id: &RunId) -> bool {
    let key = MemoryLedgerKey {
        target: PathBuf::from(LEGACY_TARGET_QUALIFIER),
        run_id: run_id.clone(),
    };
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .ledgers
        .contains_key(&key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overflowed_ledger() -> (MemoryCostLedger, InvocationId) {
        let invocation = InvocationId("overflow".to_string());
        let mut ledger = MemoryCostLedger {
            run_committed: f64::MAX,
            ..MemoryCostLedger::default()
        };
        ledger
            .invocation_committed
            .insert(invocation.clone(), f64::MAX);
        ledger.reservations.insert(
            1,
            ReservationState {
                id: 1,
                invocation_id: invocation.clone(),
                amount: f64::MAX,
            },
        );
        (ledger, invocation)
    }

    #[test]
    fn finite_legacy_totals_reject_addition_overflow() {
        let (ledger, invocation) = overflowed_ledger();

        assert!(ledger.invocation_total(&invocation).is_err());
        assert!(ledger.run_total().is_err());
        assert!(available_reservation(&ledger, &invocation, f64::MAX, f64::MAX).is_err());
    }

    #[test]
    fn legacy_reserve_propagates_existing_total_overflow() {
        let (mut ledger, invocation) = overflowed_ledger();

        assert!(ledger.reserve(&invocation, f64::MAX, f64::MAX).is_err());
    }
}
