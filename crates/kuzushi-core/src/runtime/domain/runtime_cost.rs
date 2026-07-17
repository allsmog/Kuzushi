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
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeCostReport {
    observed: RuntimeCost,
    state: RuntimeCostState,
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
}

impl RuntimeCostReport {
    pub const UNAVAILABLE: Self = Self {
        observed: RuntimeCost::ZERO,
        state: RuntimeCostState::Unavailable,
    };

    pub const INCOMPLETE_ZERO: Self = Self {
        observed: RuntimeCost::ZERO,
        state: RuntimeCostState::IncompleteObserved,
    };

    pub const fn known(cost: RuntimeCost) -> Self {
        Self {
            observed: cost,
            state: RuntimeCostState::Exact,
        }
    }

    pub const fn incomplete(observed: RuntimeCost) -> Self {
        Self {
            observed,
            state: RuntimeCostState::IncompleteObserved,
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
        if self.is_exact_zero() {
            return Ok(other);
        }
        if other.is_exact_zero() {
            return Ok(self);
        }
        if self.is_unavailable() && other.is_unavailable() {
            return Ok(Self::UNAVAILABLE);
        }
        let observed = self.observed.checked_add(other.observed, context)?;
        Ok(if self.is_unavailable() || other.is_unavailable() {
            Self::incomplete(observed)
        } else if self.is_complete() && other.is_complete() {
            Self::known(observed)
        } else {
            Self::incomplete(observed)
        })
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
        }
    }
}

impl RuntimeCostWire {
    fn into_report(self) -> Result<RuntimeCostReport> {
        let observed = RuntimeCost::from_usd(self.observed_usd, "persisted runtime cost")?;
        match self.completeness {
            RuntimeCostCompleteness::Exact => Ok(RuntimeCostReport::known(observed)),
            RuntimeCostCompleteness::IncompleteObserved => {
                Ok(RuntimeCostReport::incomplete(observed))
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
    Ok(if outcome.cost_usd_exact {
        RuntimeCostReport::known(observed)
    } else {
        RuntimeCostReport::incomplete(observed)
    })
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
