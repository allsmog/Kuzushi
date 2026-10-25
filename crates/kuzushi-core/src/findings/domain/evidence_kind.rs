use super::FindingEvidence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingEvidenceOrigin {
    ModelGeneratedReasoning,
    ReasoningAssertion,
    ObservedCapture,
    ObservedCode,
    ObservedOther,
}

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

    pub fn origin_class(&self) -> FindingEvidenceOrigin {
        if self.is_unscored_model_claim() {
            return FindingEvidenceOrigin::ModelGeneratedReasoning;
        }
        if self.kind.trim().eq_ignore_ascii_case("reasoning") {
            return FindingEvidenceOrigin::ReasoningAssertion;
        }
        observed_origin(self)
    }

    /// Compatibility predicate for non-observational reasoning kinds.
    /// Includes legacy assertions with unknown authorship.
    pub fn is_model_generated_reasoning(&self) -> bool {
        matches!(
            self.origin_class(),
            FindingEvidenceOrigin::ModelGeneratedReasoning
                | FindingEvidenceOrigin::ReasoningAssertion
        )
    }
}

fn observed_origin(evidence: &FindingEvidence) -> FindingEvidenceOrigin {
    if evidence.request_blob.is_some() || evidence.response_blob.is_some() {
        return FindingEvidenceOrigin::ObservedCapture;
    }
    if !evidence.file_path.trim().is_empty() || !evidence.snippet.trim().is_empty() {
        return FindingEvidenceOrigin::ObservedCode;
    }
    FindingEvidenceOrigin::ObservedOther
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
