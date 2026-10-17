use super::FindingEvidence;

impl FindingEvidence {
    /// These additive kinds have no calibrated numeric confidence. The legacy
    /// confidence field remains zero; consumers should label them unscored.
    pub const UNSCORED_MODEL_CLAIM: &'static str = "model-claim-unscored";
    pub const UNSCORED_SOURCE_CITATION: &'static str = "source-citation-unscored";

    pub fn is_unscored_model_claim(&self) -> bool {
        self.kind
            .trim()
            .eq_ignore_ascii_case(Self::UNSCORED_MODEL_CLAIM)
    }

    pub fn is_unscored_source_citation(&self) -> bool {
        self.kind
            .trim()
            .eq_ignore_ascii_case(Self::UNSCORED_SOURCE_CITATION)
    }

    pub fn has_unscored_confidence(&self) -> bool {
        self.is_unscored_model_claim() || self.is_unscored_source_citation()
    }

    pub fn is_model_generated_reasoning(&self) -> bool {
        self.is_unscored_model_claim() || self.kind.trim().eq_ignore_ascii_case("reasoning")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_unscored_kinds_do_not_reinterpret_legacy_zero_values() {
        for kind in [
            FindingEvidence::UNSCORED_MODEL_CLAIM,
            FindingEvidence::UNSCORED_SOURCE_CITATION,
        ] {
            let row = FindingEvidence {
                kind: kind.into(),
                ..Default::default()
            };
            assert!(row.has_unscored_confidence());
        }
        let legacy = FindingEvidence {
            kind: "reasoning".into(),
            ..Default::default()
        };
        assert!(!legacy.has_unscored_confidence());
        assert!(legacy.is_model_generated_reasoning());
    }
}
