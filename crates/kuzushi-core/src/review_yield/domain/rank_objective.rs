use crate::ReviewYieldMode;

/// What an ordering mode ranks a review band by.
///
/// The band grouping, the all-or-nothing eligibility rule, and the fingerprint
/// tie-break are identical for both: an objective chooses the key, never what a
/// row is allowed to cross.
///
/// This lives in the domain because a recorded review session names its
/// objective durably. A rank means a different thing under each key, so the
/// number and the label travel together and share one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RankObjective {
    /// Historical positive rate, highest first — review where the model says
    /// past reviewers most often confirmed.
    Yield,
    /// Model knowledge gap, widest first — review where the model's evidence
    /// is thinnest, so a verdict there teaches it the most.
    Learn,
}

impl RankObjective {
    /// The objective a mode ranks with, or `None` for a mode that never moves a
    /// row. This is the only place a mode becomes an ordering key.
    pub fn from_mode(mode: ReviewYieldMode) -> Option<Self> {
        match mode {
            ReviewYieldMode::WithinBand => Some(Self::Yield),
            ReviewYieldMode::Learn => Some(Self::Learn),
            ReviewYieldMode::Off | ReviewYieldMode::Shadow | ReviewYieldMode::Visible => None,
        }
    }

    /// The durable label recorded beside a rank.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yield => "yield",
            Self::Learn => "learn",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the two ordering modes produce an objective. A mode that promises
    /// not to move a row cannot acquire a key here.
    #[test]
    fn only_ordering_modes_have_an_objective() {
        assert_eq!(
            RankObjective::from_mode(ReviewYieldMode::WithinBand),
            Some(RankObjective::Yield)
        );
        assert_eq!(
            RankObjective::from_mode(ReviewYieldMode::Learn),
            Some(RankObjective::Learn)
        );
        for mode in [
            ReviewYieldMode::Off,
            ReviewYieldMode::Shadow,
            ReviewYieldMode::Visible,
        ] {
            assert_eq!(RankObjective::from_mode(mode), None, "{mode:?}");
        }
    }

    /// The labels are a durable schema value; renaming one silently rewrites
    /// what every stored rank claims to mean.
    #[test]
    fn objective_labels_are_stable() {
        assert_eq!(RankObjective::Yield.as_str(), "yield");
        assert_eq!(RankObjective::Learn.as_str(), "learn");
    }
}
