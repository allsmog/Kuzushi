use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A provider-reported USD amount that is safe to aggregate and persist.
///
/// Runtime cost is never allowed to be negative or non-finite. Addition is
/// checked as well because two finite values can overflow to infinity.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeCost(f64);

/// Checked provider-cost state.
///
/// `Unavailable` means no cost receipt exists (for example, a legacy persisted
/// record). `IncompleteObserved` means a provider call may have spent money but
/// did not report a complete total. Keeping those states separate prevents an
/// absent legacy receipt from being presented as an observed zero-dollar call.
///
/// An incomplete report may also carry `unmetered_estimate`: a locally priced
/// estimate (tokens × list price) covering every call that reported no charge.
/// It is never folded into `observed`; it only lets budgets and displays use a
/// labelled `~$` total instead of treating all unmetered spend as unbounded.
/// One unmetered call without an estimate makes the whole estimate unknown.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeCostReport {
    observed: RuntimeCost,
    state: RuntimeCostState,
    unmetered_estimate: Option<RuntimeCost>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeCostState {
    Exact,
    IncompleteObserved,
    Unavailable,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeCostCompleteness {
    Exact,
    IncompleteObserved,
    Unavailable,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeCostWire {
    observed_usd: f64,
    completeness: RuntimeCostCompleteness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    estimated_unmetered_usd: Option<f64>,
}

impl RuntimeCostReport {
    pub const UNAVAILABLE: Self = Self {
        observed: RuntimeCost::ZERO,
        state: RuntimeCostState::Unavailable,
        unmetered_estimate: None,
    };

    pub const INCOMPLETE_ZERO: Self = Self::incomplete(RuntimeCost::ZERO);

    pub const fn known(cost: RuntimeCost) -> Self {
        Self {
            observed: cost,
            state: RuntimeCostState::Exact,
            unmetered_estimate: None,
        }
    }

    pub const fn incomplete(observed: RuntimeCost) -> Self {
        Self {
            observed,
            state: RuntimeCostState::IncompleteObserved,
            unmetered_estimate: None,
        }
    }

    /// Attach the local estimate for the unmetered part of an incomplete
    /// report. Exact and unavailable reports are returned unchanged.
    pub const fn with_unmetered_estimate(self, estimate: Option<RuntimeCost>) -> Self {
        match self.state {
            RuntimeCostState::IncompleteObserved => Self {
                unmetered_estimate: estimate,
                ..self
            },
            _ => self,
        }
    }

    pub const fn mark_incomplete(self) -> Self {
        Self::incomplete(self.observed)
    }

    pub fn from_optional(cost_usd: Option<f64>, context: &str) -> Result<Self> {
        match cost_usd {
            Some(cost) => RuntimeCost::from_usd(cost, context).map(Self::known),
            None => Ok(Self::INCOMPLETE_ZERO),
        }
    }

    pub fn checked_add(self, other: Self, context: &str) -> Result<Self> {
        if let Some(sum) = self.trivial_sum(other) {
            return Ok(sum);
        }
        let observed = self.observed.checked_add(other.observed, context)?;
        if self.is_complete() && other.is_complete() {
            return Ok(Self::known(observed));
        }
        let estimate = self.summed_unmetered_estimate(other, context)?;
        Ok(Self::incomplete(observed).with_unmetered_estimate(estimate))
    }

    /// Sums that need no arithmetic: an exact zero is the identity, and two
    /// absent receipts stay absent.
    fn trivial_sum(self, other: Self) -> Option<Self> {
        if self.is_exact_zero() {
            return Some(other);
        }
        if other.is_exact_zero() {
            return Some(self);
        }
        (self.is_unavailable() && other.is_unavailable()).then_some(Self::UNAVAILABLE)
    }

    /// Both sides must account for their unmetered spend: an exact side adds
    /// nothing, an estimated side adds its estimate, anything else is unknown.
    fn summed_unmetered_estimate(self, other: Self, context: &str) -> Result<Option<RuntimeCost>> {
        match (
            self.unmetered_estimate_part(),
            other.unmetered_estimate_part(),
        ) {
            (Some(left), Some(right)) => left.checked_add(right, context).map(Some),
            _ => Ok(None),
        }
    }

    fn unmetered_estimate_part(self) -> Option<RuntimeCost> {
        match self.state {
            RuntimeCostState::Exact => Some(RuntimeCost::ZERO),
            RuntimeCostState::IncompleteObserved => self.unmetered_estimate,
            RuntimeCostState::Unavailable => None,
        }
    }

    /// Exact spend, or observed spend plus the unmetered estimate. `None`
    /// when some unmetered spend has no estimate; budgets must fail closed.
    pub fn estimated_total_usd(self) -> Option<f64> {
        let part = self.unmetered_estimate_part()?;
        Some(self.observed.usd() + part.usd())
    }

    /// The labelled local estimate for the unmetered part, if every unmetered
    /// call was priced. Exact reports have nothing unmetered and return `None`.
    pub fn unmetered_estimate_usd(self) -> Option<f64> {
        self.is_estimated()
            .then(|| self.unmetered_estimate.map(RuntimeCost::usd))
            .flatten()
    }

    /// True when the total is available only because of a local estimate.
    pub fn is_estimated(self) -> bool {
        self.state == RuntimeCostState::IncompleteObserved && self.unmetered_estimate.is_some()
    }

    pub fn observed_usd(self) -> f64 {
        self.observed.usd()
    }

    pub fn exact_usd(self) -> Option<f64> {
        self.is_complete().then_some(self.observed.usd())
    }

    pub fn is_complete(self) -> bool {
        self.state == RuntimeCostState::Exact
    }

    pub fn is_unavailable(self) -> bool {
        self.state == RuntimeCostState::Unavailable
    }

    pub fn observed_usd_if_available(self) -> Option<f64> {
        (!self.is_unavailable()).then_some(self.observed.usd())
    }

    fn is_exact_zero(self) -> bool {
        self.state == RuntimeCostState::Exact && self.observed.0 == 0.0
    }
}

impl Serialize for RuntimeCostReport {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RuntimeCostWire::from(*self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RuntimeCostReport {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RuntimeCostWire::deserialize(deserializer)?;
        wire.into_report().map_err(serde::de::Error::custom)
    }
}

impl From<RuntimeCostReport> for RuntimeCostWire {
    fn from(report: RuntimeCostReport) -> Self {
        let completeness = if report.is_unavailable() {
            RuntimeCostCompleteness::Unavailable
        } else if report.is_complete() {
            RuntimeCostCompleteness::Exact
        } else {
            RuntimeCostCompleteness::IncompleteObserved
        };
        Self {
            observed_usd: report.observed_usd(),
            completeness,
            estimated_unmetered_usd: report.unmetered_estimate.map(RuntimeCost::usd),
        }
    }
}

impl RuntimeCostWire {
    fn into_report(self) -> Result<RuntimeCostReport> {
        let observed = RuntimeCost::from_usd(self.observed_usd, "persisted runtime cost")?;
        match self.completeness {
            RuntimeCostCompleteness::Exact => Ok(RuntimeCostReport::known(observed)),
            RuntimeCostCompleteness::IncompleteObserved => {
                let estimate = self
                    .estimated_unmetered_usd
                    .map(|usd| RuntimeCost::from_usd(usd, "persisted runtime cost estimate"))
                    .transpose()?;
                Ok(RuntimeCostReport::incomplete(observed).with_unmetered_estimate(estimate))
            }
            RuntimeCostCompleteness::Unavailable => {
                anyhow::ensure!(
                    observed == RuntimeCost::ZERO,
                    "unavailable cost must be zero"
                );
                Ok(RuntimeCostReport::UNAVAILABLE)
            }
        }
    }
}

impl RuntimeCost {
    pub const ZERO: Self = Self(0.0);

    pub fn from_usd(cost_usd: f64, context: &str) -> Result<Self> {
        anyhow::ensure!(
            cost_usd.is_finite() && cost_usd >= 0.0,
            "{context} must be a finite non-negative USD amount, got {cost_usd}"
        );
        Ok(Self(if cost_usd == 0.0 { 0.0 } else { cost_usd }))
    }

    pub fn checked_add(self, other: Self, context: &str) -> Result<Self> {
        Self::from_usd(self.0 + other.0, context)
            .with_context(|| format!("could not add {} + {}", self.0, other.0))
    }

    pub fn checked_sub(self, other: Self, context: &str) -> Result<Self> {
        anyhow::ensure!(
            other.0 <= self.0,
            "{context} cannot subtract {} from {}",
            other.0,
            self.0
        );
        Self::from_usd(self.0 - other.0, context)
    }

    pub fn checked_sum(costs: impl IntoIterator<Item = f64>, context: &str) -> Result<Self> {
        costs.into_iter().try_fold(Self::ZERO, |total, cost| {
            let cost = Self::from_usd(cost, context)?;
            total.checked_add(cost, context)
        })
    }

    pub fn usd(self) -> f64 {
        self.0
    }
}

pub fn triage_cost_report(outcome: &crate::findings::TriageOutcome) -> Result<RuntimeCostReport> {
    let observed = RuntimeCost::from_usd(outcome.cost_usd, "triage outcome cost")?;
    if outcome.cost_usd_exact {
        return Ok(RuntimeCostReport::known(observed));
    }
    let estimate = outcome
        .estimated_cost_usd
        .map(|usd| RuntimeCost::from_usd(usd, "triage outcome estimated cost"))
        .transpose()?;
    Ok(RuntimeCostReport::incomplete(observed).with_unmetered_estimate(estimate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_zero_and_finite_non_negative_values() {
        assert_eq!(RuntimeCost::from_usd(0.0, "cost").unwrap().usd(), 0.0);
        assert_eq!(RuntimeCost::from_usd(1.25, "cost").unwrap().usd(), 1.25);
    }

    #[test]
    fn rejects_negative_and_non_finite_values() {
        for invalid in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(RuntimeCost::from_usd(invalid, "provider cost").is_err());
        }
    }

    #[test]
    fn checked_sum_rejects_finite_addition_overflow() {
        let error = RuntimeCost::checked_sum([f64::MAX, f64::MAX], "fan-out cost")
            .unwrap_err()
            .to_string();
        assert!(error.contains("could not add"), "{error}");
    }

    #[test]
    fn report_keeps_incomplete_unavailable_and_reported_zero_distinct() {
        let incomplete = RuntimeCostReport::from_optional(None, "cost").unwrap();
        let unavailable = RuntimeCostReport::UNAVAILABLE;
        let zero = RuntimeCostReport::from_optional(Some(0.0), "cost").unwrap();
        assert_eq!(incomplete.exact_usd(), None);
        assert_eq!(incomplete.observed_usd_if_available(), Some(0.0));
        assert!(!incomplete.is_unavailable());
        assert_eq!(unavailable.observed_usd_if_available(), None);
        assert!(unavailable.is_unavailable());
        assert_eq!(zero.exact_usd(), Some(0.0));
    }

    #[test]
    fn exact_zero_is_the_additive_identity_for_every_report_state() {
        let zero = RuntimeCostReport::known(RuntimeCost::ZERO);
        let exact = RuntimeCostReport::known(RuntimeCost::from_usd(0.25, "cost").unwrap());
        let incomplete = RuntimeCostReport::incomplete(RuntimeCost::from_usd(0.1, "cost").unwrap());

        assert_eq!(zero.checked_add(exact, "sum").unwrap(), exact);
        assert_eq!(zero.checked_add(incomplete, "sum").unwrap(), incomplete);
        assert_eq!(
            zero.checked_add(RuntimeCostReport::UNAVAILABLE, "sum")
                .unwrap(),
            RuntimeCostReport::UNAVAILABLE
        );
        assert_eq!(
            RuntimeCostReport::UNAVAILABLE
                .checked_add(zero, "sum")
                .unwrap(),
            RuntimeCostReport::UNAVAILABLE
        );
    }

    #[test]
    fn unavailable_preserves_observed_subtotals_without_inventing_exactness() {
        let exact = RuntimeCostReport::known(RuntimeCost::from_usd(0.25, "cost").unwrap());
        let incomplete = RuntimeCostReport::incomplete(RuntimeCost::from_usd(0.1, "cost").unwrap());

        assert_eq!(
            RuntimeCostReport::UNAVAILABLE
                .checked_add(exact, "sum")
                .unwrap(),
            RuntimeCostReport::incomplete(RuntimeCost::from_usd(0.25, "cost").unwrap())
        );
        assert_eq!(
            RuntimeCostReport::incomplete(RuntimeCost::from_usd(0.25, "cost").unwrap())
                .checked_add(RuntimeCostReport::UNAVAILABLE, "sum")
                .unwrap(),
            RuntimeCostReport::incomplete(RuntimeCost::from_usd(0.25, "cost").unwrap())
        );
        assert_eq!(
            RuntimeCostReport::UNAVAILABLE
                .checked_add(incomplete, "sum")
                .unwrap(),
            incomplete
        );
        assert_eq!(
            RuntimeCostReport::UNAVAILABLE
                .checked_add(RuntimeCostReport::UNAVAILABLE, "sum")
                .unwrap(),
            RuntimeCostReport::UNAVAILABLE
        );
    }

    fn usd(value: f64) -> RuntimeCost {
        RuntimeCost::from_usd(value, "cost").unwrap()
    }

    #[test]
    fn estimate_totals_only_when_every_unmetered_part_is_estimated() {
        let exact = RuntimeCostReport::known(usd(0.25));
        let estimated = RuntimeCostReport::INCOMPLETE_ZERO.with_unmetered_estimate(Some(usd(0.5)));
        let unknown = RuntimeCostReport::INCOMPLETE_ZERO;

        let sum = exact.checked_add(estimated, "sum").unwrap();
        assert_eq!(sum.exact_usd(), None);
        assert!(sum.is_estimated());
        assert_eq!(sum.estimated_total_usd(), Some(0.75));
        assert_eq!(sum.observed_usd(), 0.25, "the estimate never becomes spend");

        let with_unknown = sum.checked_add(unknown, "sum").unwrap();
        assert!(!with_unknown.is_estimated());
        assert_eq!(with_unknown.estimated_total_usd(), None);
        let with_unavailable = estimated
            .checked_add(RuntimeCostReport::UNAVAILABLE, "sum")
            .unwrap();
        assert_eq!(with_unavailable.estimated_total_usd(), None);
        assert_eq!(exact.estimated_total_usd(), Some(0.25));
        assert!(!exact.is_estimated());
    }

    #[test]
    fn long_float_estimates_survive_a_persisted_round_trip_exactly() {
        // Run items are hash-checked by re-serializing what was read, so a
        // 17-digit estimate must parse back to the identical f64.
        let estimate = 0.1025612_f64 + 1e-17;
        let summed = usd(0.1)
            .checked_add(usd(estimate - 0.1), "sum")
            .unwrap()
            .usd();
        let report = RuntimeCostReport::INCOMPLETE_ZERO.with_unmetered_estimate(Some(usd(summed)));
        let text = serde_json::to_string(&report).unwrap();
        let back: RuntimeCostReport = serde_json::from_str(&text).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
        for literal in ["0.10256119999999999", "0.20925020000000003"] {
            let value: f64 = serde_json::from_str(literal).unwrap();
            assert_eq!(serde_json::to_string(&value).unwrap(), literal);
        }
    }

    #[test]
    fn estimates_attach_only_to_incomplete_reports_and_round_trip() {
        let exact = RuntimeCostReport::known(usd(0.25));
        assert_eq!(exact.with_unmetered_estimate(Some(usd(1.0))), exact);
        assert_eq!(
            RuntimeCostReport::UNAVAILABLE.with_unmetered_estimate(Some(usd(1.0))),
            RuntimeCostReport::UNAVAILABLE
        );

        let estimated =
            RuntimeCostReport::incomplete(usd(0.1)).with_unmetered_estimate(Some(usd(0.2)));
        let wire = serde_json::to_value(estimated).unwrap();
        assert_eq!(wire["estimatedUnmeteredUsd"], 0.2);
        let back: RuntimeCostReport = serde_json::from_value(wire).unwrap();
        assert_eq!(back, estimated);

        let legacy = serde_json::json!({"observedUsd": 0.1, "completeness": "incomplete_observed"});
        let legacy: RuntimeCostReport = serde_json::from_value(legacy).unwrap();
        assert!(!legacy.is_estimated());
        let exact_wire = serde_json::to_value(exact).unwrap();
        assert!(exact_wire.get("estimatedUnmeteredUsd").is_none());
    }

    #[test]
    fn triage_report_carries_the_outcome_estimate() {
        let estimated = crate::findings::TriageOutcome {
            cost_usd_exact: false,
            estimated_cost_usd: Some(0.02),
            ..Default::default()
        };
        let report = triage_cost_report(&estimated).unwrap();
        assert_eq!(report.estimated_total_usd(), Some(0.02));
        assert_eq!(report.exact_usd(), None);
    }

    #[test]
    fn triage_report_keeps_unknown_distinct_from_reported_zero() {
        let unknown = crate::findings::TriageOutcome {
            cost_usd_exact: false,
            ..Default::default()
        };
        let zero = crate::findings::TriageOutcome::default();

        assert_eq!(triage_cost_report(&unknown).unwrap().exact_usd(), None);
        assert!(!triage_cost_report(&unknown).unwrap().is_unavailable());
        assert_eq!(triage_cost_report(&zero).unwrap().exact_usd(), Some(0.0));
    }
}
