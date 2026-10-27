//! Whether the owned study is bounded by its own spending allowance.
//!
//! A session cost-cap halt never stops an owned study, so halt messaging must
//! say honestly whether that study is bounded at all. The answer comes from
//! the study's recorded campaign state; unreadable state stays `Unknown`.
use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum StudyAllowance {
    /// An approved study allowance or a recorded campaign USD cap applies.
    Set,
    /// The campaign records neither an approved allowance nor a USD cap.
    NotSet,
    /// The campaign state could not be read, so the bound is undetermined.
    #[default]
    Unknown,
}

impl StudyAllowance {
    fn classify(approved: Result<bool>, capped: Result<bool>) -> Self {
        match (approved, capped) {
            (Ok(true), _) | (_, Ok(true)) => Self::Set,
            (Ok(false), Ok(false)) => Self::NotSet,
            _ => Self::Unknown,
        }
    }
}

/// Reads the study's approved allowance and recorded campaign caps.
pub(crate) fn resolve_study_allowance(target: &Path, campaign: &str) -> StudyAllowance {
    StudyAllowance::classify(
        has_approved_allowance(target, campaign),
        has_recorded_usd_cap(target, campaign),
    )
}

fn has_approved_allowance(target: &Path, campaign: &str) -> Result<bool> {
    let workspace = kuzushi_core::WorkspaceTarget::new(target)?;
    let allowance = kuzushi_core::SpendLimiter::read_campaign_allowance(
        &workspace.findings_db_path(),
        campaign,
    )?;
    Ok(allowance.is_some())
}

fn has_recorded_usd_cap(target: &Path, campaign: &str) -> Result<bool> {
    let snapshot =
        kuzushi_core::capabilities::campaign::snapshot::load_campaign_snapshot(target, campaign)?;
    let positive = |usd: Option<f64>| usd.is_some_and(|usd| usd > 0.0);
    Ok(positive(snapshot.budget_usd) || positive(snapshot.job_budget_usd))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unreadable() -> Result<bool> {
        Err(anyhow::anyhow!("unreadable"))
    }

    #[test]
    fn any_known_bound_sets_the_allowance() {
        assert_eq!(
            StudyAllowance::classify(Ok(true), unreadable()),
            StudyAllowance::Set
        );
        assert_eq!(
            StudyAllowance::classify(unreadable(), Ok(true)),
            StudyAllowance::Set
        );
    }

    #[test]
    fn only_fully_readable_absence_is_not_set() {
        assert_eq!(
            StudyAllowance::classify(Ok(false), Ok(false)),
            StudyAllowance::NotSet
        );
        assert_eq!(
            StudyAllowance::classify(Ok(false), unreadable()),
            StudyAllowance::Unknown
        );
        assert_eq!(
            StudyAllowance::classify(unreadable(), Ok(false)),
            StudyAllowance::Unknown
        );
    }

    #[test]
    fn a_missing_plan_is_unknown_rather_than_unbounded() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_study_allowance(root.path(), "absent"),
            StudyAllowance::Unknown
        );
    }
}
