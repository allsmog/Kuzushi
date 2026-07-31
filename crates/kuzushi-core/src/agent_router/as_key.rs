#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentRole {
    /// Single-pass triage on a finding (existing default path).
    Triage,
    /// Cheap classifier gate before deep-audit (Phase 6).
    ClassifierGate,
    /// Tool-augmented deep auditor (Phase 5).
    DeepAuditor,
    /// Whole-codebase chunked LLM pass (Phase 7).
    FullModeMulti,
    /// Existing systems-hunt module.
    SystemsHunt,
    /// Existing carlini-threat-hunt module.
    Carlini,
    /// Existing variant-ndiff module.
    VariantNdiff,
    /// threat-model build / random.
    ThreatModel,
    /// x-ray architecture-doc module.
    XRay,
    /// patch-finding module.
    Patch,
    /// Different tie-break model consulted only when a consensus verdict splits
    /// evenly (deep-audit and verify escalation). Never inherited — it must be
    /// operator-named, or the split verdict stands.
    TriageEscalation,
}

impl AgentRole {
    pub fn as_key(self) -> &'static str {
        match self {
            Self::Triage => "triage",
            Self::ClassifierGate => "classifier_gate",
            Self::DeepAuditor => "deep_auditor",
            Self::FullModeMulti => "full_mode_multi",
            Self::SystemsHunt => "systems_hunt",
            Self::Carlini => "carlini",
            Self::VariantNdiff => "variant_ndiff",
            Self::ThreatModel => "threat_model",
            Self::XRay => "x_ray",
            Self::Patch => "patch",
            Self::TriageEscalation => "triage_escalation",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "triage" => Some(Self::Triage),
            "classifier_gate" => Some(Self::ClassifierGate),
            "deep_auditor" => Some(Self::DeepAuditor),
            "full_mode_multi" => Some(Self::FullModeMulti),
            "systems_hunt" => Some(Self::SystemsHunt),
            "carlini" => Some(Self::Carlini),
            "variant_ndiff" => Some(Self::VariantNdiff),
            "threat_model" => Some(Self::ThreatModel),
            "x_ray" => Some(Self::XRay),
            "patch" => Some(Self::Patch),
            "triage_escalation" => Some(Self::TriageEscalation),
            _ => None,
        }
    }

    /// Option-store key used to set this role's model from `setg`/`set`:
    ///   `setg MODEL_DEEP_AUDITOR anthropic:claude-opus-4-7`
    pub fn option_store_key(self) -> String {
        format!("MODEL_{}", self.as_key().to_uppercase())
    }

    /// Iterate over every role. Used to enumerate option specs and
    /// docs surfaces.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Triage,
            Self::ClassifierGate,
            Self::DeepAuditor,
            Self::FullModeMulti,
            Self::SystemsHunt,
            Self::Carlini,
            Self::VariantNdiff,
            Self::ThreatModel,
            Self::XRay,
            Self::Patch,
            Self::TriageEscalation,
        ]
    }
}
