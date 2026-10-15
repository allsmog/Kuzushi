//! Recorded presence and coverage do not determine a finding verdict.
use super::ComparedFinding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanObservationPresence {
    NewlyObserved,
    SeenAgain,
    NotObserved,
    NotReassessed,
    Unknown,
}

impl ScanObservationPresence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewlyObserved => "newly_observed",
            Self::SeenAgain => "seen_again",
            Self::NotObserved => "not_observed",
            Self::NotReassessed => "not_reassessed",
            Self::Unknown => "unknown",
        }
    }
}

impl ComparedFinding {
    /// Uses recorded observations and coverage, independently of legacy classes.
    pub fn observation_presence(&self) -> ScanObservationPresence {
        if self.after.is_some() {
            return observed_presence(self.before.is_some());
        }
        if self.before.is_none() {
            return ScanObservationPresence::Unknown;
        }
        if self.reassessment_block.is_some() {
            return ScanObservationPresence::NotReassessed;
        }
        ScanObservationPresence::NotObserved
    }
}

fn observed_presence(seen_before: bool) -> ScanObservationPresence {
    if seen_before {
        ScanObservationPresence::SeenAgain
    } else {
        ScanObservationPresence::NewlyObserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{ScanComparisonClass, ScanFindingSignature};

    fn absent() -> ComparedFinding {
        ComparedFinding {
            stable_key: "owned-policy".into(),
            title: "Owned policy signal".into(),
            file_path: "note.md".into(),
            tool: "semgrep".into(),
            class: ScanComparisonClass::Resolved,
            reason: None,
            before: Some(ScanFindingSignature::default()),
            after: None,
            reassessment_block: None,
        }
    }

    #[test]
    fn legacy_resolution_with_missing_receipt_remains_not_reassessed() {
        let mut row = absent();
        row.reassessment_block = Some("scan coverage receipt is unavailable".into());
        assert_eq!(
            row.observation_presence(),
            ScanObservationPresence::NotReassessed
        );
        row.reassessment_block = None;
        assert_eq!(
            row.observation_presence(),
            ScanObservationPresence::NotObserved
        );
        assert_eq!(row.class, ScanComparisonClass::Resolved);
    }

    #[test]
    fn seen_again_and_new_observations_do_not_claim_fix_or_introduction() {
        let mut row = absent();
        row.after = Some(ScanFindingSignature::default());
        assert_eq!(
            row.observation_presence(),
            ScanObservationPresence::SeenAgain
        );
        row.before = None;
        assert_eq!(
            row.observation_presence(),
            ScanObservationPresence::NewlyObserved
        );
    }

    #[test]
    fn missing_observations_cannot_prove_absence() {
        let mut row = absent();
        row.before = None;
        assert_eq!(row.observation_presence(), ScanObservationPresence::Unknown);
    }
}
