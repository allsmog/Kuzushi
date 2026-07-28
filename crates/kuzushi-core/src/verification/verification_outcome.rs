use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofVerdict {
    /// Runtime verification was deliberately not started because a safety or
    /// harness-fidelity prerequisite was not met.
    NotAttempted,
    /// An observed exploit triggered inside the sandbox.
    Exploited,
    /// Harness compiled and ran but the suspect path didn't crash.
    /// Could be a true negative or insufficient trigger synthesis.
    NotReproduced,
    /// Harness failed to compile — finding is at minimum well-formed
    /// at the structural level but the trigger wasn't expressible.
    HarnessFailedToBuild,
    /// Sandbox or other infrastructure failed before observation.
    InfrastructureError,
    /// Language not yet supported by the verify pipeline.
    LanguageUnsupportedYet,
    /// Finding lacks the structural information needed to verify
    /// (e.g. no file/line, or location does not exist on disk).
    InsufficientFindingDetail,
}

impl ProofVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::Exploited => "exploited",
            Self::NotReproduced => "not_reproduced",
            Self::HarnessFailedToBuild => "harness_failed_to_build",
            Self::InfrastructureError => "infrastructure_error",
            Self::LanguageUnsupportedYet => "language_unsupported_yet",
            Self::InsufficientFindingDetail => "insufficient_finding_detail",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationOutcome {
    pub proof_level: u8,
    pub proof_verdict: ProofVerdict,
    pub backend: SandboxBackend,
    /// Language adapter that produced this outcome (e.g. `"rust"`).
    /// Set by [`verify_finding`]; adapters leave it `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash_evidence: Option<String>,
    pub duration_ms: u64,
    pub cost_usd: f64,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::findings::VerificationProvenance>,
}
