use super::feature_schema::ReviewYieldFeaturesV1;

/// One feature as a tree node sees it.
///
/// `Missing` is a real, reportable state (design §10.1): the finding carries no
/// value for a feature the schema defines. It is not the same as a name the
/// schema does not define at all, which the lookup reports as `None`.
#[derive(Debug, Clone, PartialEq)]
pub enum FeatureValue {
    Number(f64),
    Category(String),
    Boolean(bool),
    Missing,
}

/// The evaluator's whole view of a finding. Keeping it a trait lets the parity
/// tests drive the same evaluator from the fixture's raw feature maps.
pub trait FeatureLookup {
    /// `None` when the name is not in this feature schema at all.
    fn feature(&self, name: &str) -> Option<FeatureValue>;
}

impl FeatureLookup for ReviewYieldFeaturesV1 {
    fn feature(&self, name: &str) -> Option<FeatureValue> {
        self.categorical_feature(name)
            .or_else(|| self.count_feature(name))
            .or_else(|| self.boolean_feature(name))
    }
}

impl ReviewYieldFeaturesV1 {
    fn categorical_feature(&self, name: &str) -> Option<FeatureValue> {
        let value = match name {
            "staticProofState" => &self.static_proof_state,
            "vulnSource" => &self.vuln_source,
            "toolFamily" => &self.tool_family,
            "ruleFamily" => &self.rule_family,
            "pathBucket" => &self.path_bucket,
            "languageFamily" => &self.language_family,
            "identityMatchTier" => &self.identity_match_tier,
            "groundingStatus" => &self.grounding_status,
            _ => return None,
        };
        Some(FeatureValue::Category(value.clone()))
    }

    fn count_feature(&self, name: &str) -> Option<FeatureValue> {
        let value: f64 = match name {
            "severityRank" => f64::from(self.severity_rank),
            "evidenceCount" => f64::from(self.evidence_count),
            "distinctEvidenceKinds" => f64::from(self.distinct_evidence_kinds),
            "maxEvidenceConfidence" => return Some(optional(self.max_evidence_confidence)),
            "meanEvidenceConfidenceMillis" => {
                return Some(optional(self.mean_evidence_confidence_millis))
            }
            "preconditionCount" => f64::from(self.precondition_count),
            "sourceCount" => f64::from(self.source_count),
            "distinctToolCount" => f64::from(self.distinct_tool_count),
            "corroborationCount" => f64::from(self.corroboration_count),
            "observationCount" => f64::from(self.observation_count),
            "runCount" => f64::from(self.run_count),
            "reopenedCount" => f64::from(self.reopened_count),
            _ => return None,
        };
        Some(FeatureValue::Number(value))
    }

    fn boolean_feature(&self, name: &str) -> Option<FeatureValue> {
        let value = match name {
            "isAttackChain" => self.is_attack_chain,
            "hasSourceEvidence" => self.has_source_evidence,
            "hasSinkEvidence" => self.has_sink_evidence,
            "hasSanitizerEvidence" => self.has_sanitizer_evidence,
            "hasCallPathEvidence" => self.has_call_path_evidence,
            "sourceSinkLinked" => self.source_sink_linked,
            "sanitizerChecked" => self.sanitizer_checked,
            "hasExploitScenario" => self.has_exploit_scenario,
            "hasRemediation" => self.has_remediation,
            _ => return None,
        };
        Some(FeatureValue::Boolean(value))
    }
}

/// An optional count: absent stays absent instead of becoming zero.
fn optional<T: Into<f64>>(value: Option<T>) -> FeatureValue {
    match value {
        Some(number) => FeatureValue::Number(number.into()),
        None => FeatureValue::Missing,
    }
}
