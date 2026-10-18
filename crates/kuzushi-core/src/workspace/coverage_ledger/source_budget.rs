//! One finite allowance shared by initial history inspection and revalidation.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SourceComparisonLimits {
    pub max_comparisons: usize,
    pub max_diff_bytes: usize,
}

impl Default for SourceComparisonLimits {
    fn default() -> Self {
        Self {
            max_comparisons: 32,
            max_diff_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SourceComparisonBudget {
    limits: SourceComparisonLimits,
    comparisons: usize,
    diff_bytes: usize,
}

impl SourceComparisonBudget {
    pub(crate) fn new(limits: SourceComparisonLimits) -> Result<Self> {
        anyhow::ensure!(
            (1..=512).contains(&limits.max_comparisons),
            "maxSourceComparisons must be between 1 and 512"
        );
        anyhow::ensure!(
            (1..=67_108_864).contains(&limits.max_diff_bytes),
            "maxDiffBytes must be between 1 and 67108864"
        );
        Ok(Self {
            limits,
            comparisons: 0,
            diff_bytes: 0,
        })
    }

    pub(super) fn reserve_diff(&mut self) -> Result<usize> {
        anyhow::ensure!(self.comparisons < self.limits.max_comparisons,
            "Historical source comparison reached maxSourceComparisons={}; no new baselines were written. Review the workload before explicitly changing the limit.", self.limits.max_comparisons);
        let remaining = self.limits.max_diff_bytes.saturating_sub(self.diff_bytes);
        anyhow::ensure!(remaining > 0,
            "Historical source comparison reached maxDiffBytes={}; no new baselines were written. Review the workload before explicitly changing the limit.", self.limits.max_diff_bytes);
        self.comparisons += 1;
        Ok(remaining)
    }

    pub(super) fn record_bytes(&mut self, bytes: usize) -> Result<()> {
        let total = self
            .diff_bytes
            .checked_add(bytes)
            .context("Historical diff byte count overflow")?;
        anyhow::ensure!(
            total <= self.limits.max_diff_bytes,
            "Historical diff output exceeded maxDiffBytes; no new baselines were written"
        );
        self.diff_bytes = total;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservations_charge_attempts_and_share_remaining_output_bytes() {
        let mut budget = SourceComparisonBudget::new(SourceComparisonLimits {
            max_comparisons: 2,
            max_diff_bytes: 7,
        })
        .unwrap();
        assert_eq!(budget.reserve_diff().unwrap(), 7);
        budget.record_bytes(5).unwrap();
        assert_eq!(budget.reserve_diff().unwrap(), 2);
        assert!(budget
            .reserve_diff()
            .unwrap_err()
            .to_string()
            .contains("maxSourceComparisons=2"));
        budget.record_bytes(2).unwrap();
        assert_eq!(budget.comparisons, 2);
        assert_eq!(budget.diff_bytes, 7);
    }
    #[test]
    fn exhausted_output_and_invalid_limits_never_grant_more_work() {
        let mut budget = SourceComparisonBudget::new(SourceComparisonLimits {
            max_comparisons: 2,
            max_diff_bytes: 1,
        })
        .unwrap();
        budget.reserve_diff().unwrap();
        budget.record_bytes(1).unwrap();
        assert!(budget
            .reserve_diff()
            .unwrap_err()
            .to_string()
            .contains("maxDiffBytes=1"));
        assert!(budget.record_bytes(usize::MAX).is_err());
        for limits in [
            SourceComparisonLimits {
                max_comparisons: 0,
                max_diff_bytes: 1,
            },
            SourceComparisonLimits {
                max_comparisons: 1,
                max_diff_bytes: 0,
            },
        ] {
            assert!(SourceComparisonBudget::new(limits).is_err());
        }
    }
}
