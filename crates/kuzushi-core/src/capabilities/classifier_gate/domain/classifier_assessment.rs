use super::Score;

/// What the classifier gate learned about one candidate finding.
///
/// A response the gate could not parse is not a score. Representing it as one
/// let a parse failure be persisted as a model judgement and — under the
/// default cold-start floor — silently reject the finding it failed to read.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClassifierAssessment {
    /// The model returned a usable verdict.
    Scored(Score),
    /// The model answered, but the answer carried no usable verdict.
    ParseDegraded,
}

impl ClassifierAssessment {
    /// The score the model actually produced, if it produced one.
    pub fn score(self) -> Option<Score> {
        match self {
            Self::Scored(score) => Some(score),
            Self::ParseDegraded => None,
        }
    }

    pub fn is_parse_degraded(self) -> bool {
        matches!(self, Self::ParseDegraded)
    }
}

/// A bare score is a scored assessment. This keeps callers written against the
/// score-only gate API compiling against the assessment-taking one.
impl From<Score> for ClassifierAssessment {
    fn from(score: Score) -> Self {
        Self::Scored(score)
    }
}
