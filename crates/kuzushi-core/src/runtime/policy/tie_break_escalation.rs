use super::canonical_model_spec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TieBreakRefusal {
    SameModelAsPrimary,
    InvalidModelSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TieBreakEscalation {
    NotRequested,
    Refused(TieBreakRefusal),
    Escalate(String),
}

impl TieBreakRefusal {
    /// Single owner of the operator-facing refusal wording.
    pub fn operator_message(self) -> &'static str {
        match self {
            Self::SameModelAsPrimary =>
                "tie-break escalation model equals the primary model; a same-model escalation cannot break the tie and was refused (verdict unchanged)",
            Self::InvalidModelSpec =>
                "tie-break escalation model is not a valid provider:modelId spec; escalation refused (verdict unchanged)",
        }
    }

    /// Short, space-free token for the durable stage-note grammar.
    pub fn token(self) -> &'static str {
        match self {
            Self::SameModelAsPrimary => "same-model",
            Self::InvalidModelSpec => "invalid-spec",
        }
    }
}

/// Decide whether a split verdict escalates. Pure; no runtime, no IO. Absence is
/// the truthful default (NotRequested); refusal is disclosed, never substituted.
pub fn decide_tie_break(primary: &str, escalation: Option<&str>) -> TieBreakEscalation {
    let Some(raw) = escalation.map(str::trim).filter(|s| !s.is_empty()) else {
        return TieBreakEscalation::NotRequested;
    };
    let Ok(escalated) = canonical_model_spec(raw) else {
        return TieBreakEscalation::Refused(TieBreakRefusal::InvalidModelSpec);
    };
    match canonical_model_spec(primary) {
        Ok(primary) if primary == escalated => {
            TieBreakEscalation::Refused(TieBreakRefusal::SameModelAsPrimary)
        }
        _ => TieBreakEscalation::Escalate(escalated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_escalation_is_not_requested() {
        assert_eq!(
            decide_tie_break("anthropic:primary", None),
            TieBreakEscalation::NotRequested
        );
        assert_eq!(
            decide_tie_break("anthropic:primary", Some("   ")),
            TieBreakEscalation::NotRequested
        );
    }

    #[test]
    fn same_model_with_different_spelling_is_refused() {
        assert_eq!(
            decide_tie_break("anthropic:m", Some(" anthropic : m ")),
            TieBreakEscalation::Refused(TieBreakRefusal::SameModelAsPrimary)
        );
    }

    #[test]
    fn invalid_spec_is_refused() {
        assert_eq!(
            decide_tie_break("anthropic:primary", Some("nonsense")),
            TieBreakEscalation::Refused(TieBreakRefusal::InvalidModelSpec)
        );
    }

    #[test]
    fn distinct_escalation_is_canonicalized() {
        assert_eq!(
            decide_tie_break("anthropic:primary", Some("  openai : bigger ")),
            TieBreakEscalation::Escalate("openai:bigger".to_string())
        );
    }
}
