use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PatchAttempt {
    pub attempt: usize,
    pub diff: String,
    pub status: PatchStatus,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PatchResult {
    pub patch_run_id: String,
    pub fingerprint: String,
    pub repo: String,
    pub diff: Option<String>,
    pub status: PatchStatus,
    pub iterations: usize,
    pub build_command: Option<String>,
    pub test_command: Option<String>,
    pub worktree_path: Option<String>,
    /// Provider-observed patch synthesis subtotal. `None` is unavailable,
    /// never an inferred exact zero.
    pub cost_usd: Option<f64>,
    /// True when at least one paid synthesis call did not return trustworthy
    /// provider usage. Legacy results with a cost and no bit remain exact;
    /// legacy results with no cost remain unavailable.
    #[serde(default, skip_serializing_if = "is_false")]
    pub provider_spend_unresolved: bool,
    pub validator_log: Option<String>,
    pub history: Vec<PatchAttempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl PatchResult {
    pub fn validated_cost_usd(&self) -> Result<Option<f64>> {
        if let Some(cost_usd) = self.cost_usd {
            anyhow::ensure!(
                cost_usd.is_finite() && cost_usd >= 0.0,
                "patch result cost must be a finite non-negative USD amount, got {cost_usd}"
            );
        }
        anyhow::ensure!(
            !self.provider_spend_unresolved || self.cost_usd.is_some(),
            "patch result unresolved provider spend requires an observed cost subtotal"
        );
        Ok(self.cost_usd)
    }
}

const fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod patch_cost_tests {
    use super::*;

    #[test]
    fn legacy_patch_cost_accepts_a_cost_or_an_unavailable_receipt() {
        let with_cost = patch_result_from_json(Some(0.0));
        let without_cost = patch_result_from_json(None);

        assert_eq!(with_cost.validated_cost_usd().unwrap(), Some(0.0));
        assert_eq!(without_cost.validated_cost_usd().unwrap(), None);
    }

    #[test]
    fn unresolved_patch_cost_bit_round_trips() {
        let mut result = patch_result_from_json(Some(0.25));
        result.provider_spend_unresolved = true;

        let encoded = serde_json::to_value(&result).unwrap();
        let decoded: PatchResult = serde_json::from_value(encoded).unwrap();

        assert_eq!(decoded.cost_usd, Some(0.25));
        assert!(decoded.provider_spend_unresolved);
        assert_eq!(decoded.validated_cost_usd().unwrap(), Some(0.25));
    }

    #[test]
    fn rejects_invalid_or_unbacked_patch_cost_state() {
        for invalid in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut result = patch_result_from_json(Some(0.0));
            result.cost_usd = Some(invalid);
            assert!(result.validated_cost_usd().is_err());
        }
        let mut unresolved_without_observation = patch_result_from_json(None);
        unresolved_without_observation.provider_spend_unresolved = true;
        assert!(unresolved_without_observation.validated_cost_usd().is_err());
    }

    fn patch_result_from_json(cost_usd: Option<f64>) -> PatchResult {
        serde_json::from_value(serde_json::json!({
            "patchRunId": "patch-legacy",
            "fingerprint": "fp",
            "repo": "/repo",
            "diff": null,
            "status": "UNKNOWN",
            "iterations": 0,
            "buildCommand": null,
            "testCommand": null,
            "worktreePath": null,
            "costUsd": cost_usd,
            "validatorLog": null,
            "history": [],
        }))
        .unwrap()
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TriageVerdict {
    TruePositive,
    FalsePositive,
    /// Default — used when no verdict has been assigned yet (or when
    /// a provider failed to produce one). Conservative by design.
    #[default]
    NeedsReview,
    ByDesign,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TriageAuthor {
    Human,
    Auto,
    Imported,
}

impl TriageAuthor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Auto => "auto",
            Self::Imported => "imported",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "human" => Self::Human,
            "auto" => Self::Auto,
            "imported" => Self::Imported,
            _ => return None,
        })
    }
}

impl TriageVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TruePositive => "true_positive",
            Self::FalsePositive => "false_positive",
            Self::NeedsReview => "needs_review",
            Self::ByDesign => "by_design",
        }
    }
}

impl TryFrom<&str> for TriageVerdict {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "true_positive" => Ok(Self::TruePositive),
            "false_positive" => Ok(Self::FalsePositive),
            "needs_review" => Ok(Self::NeedsReview),
            "by_design" => Ok(Self::ByDesign),
            other => anyhow::bail!("unknown triage verdict {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PersistedVerification {
    pub proof_level: u8,
    pub proof_verdict: PersistedProofVerdict,
    pub backend: PersistedSandboxBackend,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash_evidence: Option<String>,
    pub duration_ms: u64,
    pub cost_usd: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Run that produced the empirical verification. This is deliberately
    /// distinct from `Finding.scan_id`, which names the discovery observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_run_id: Option<String>,
    /// Discovery observation that was current when verification ran. A later
    /// observation with the same durable identity may reuse the proof, but the
    /// UI can then label it as requiring revalidation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_scan_id: Option<String>,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PersistedProofVerdict {
    Exploited,
    NotReproduced,
    HarnessFailedToBuild,
    InfrastructureError,
    LanguageUnsupportedYet,
    InsufficientFindingDetail,
}

impl PersistedProofVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exploited => "exploited",
            Self::NotReproduced => "not_reproduced",
            Self::HarnessFailedToBuild => "harness_failed_to_build",
            Self::InfrastructureError => "infrastructure_error",
            Self::LanguageUnsupportedYet => "language_unsupported_yet",
            Self::InsufficientFindingDetail => "insufficient_finding_detail",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "exploited" => Self::Exploited,
            "not_reproduced" => Self::NotReproduced,
            "harness_failed_to_build" => Self::HarnessFailedToBuild,
            "infrastructure_error" => Self::InfrastructureError,
            "language_unsupported_yet" => Self::LanguageUnsupportedYet,
            "insufficient_finding_detail" => Self::InsufficientFindingDetail,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PersistedSandboxBackend {
    Bwrap,
    Podman,
    Plain,
}

impl PersistedSandboxBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bwrap => "bwrap",
            Self::Podman => "podman",
            Self::Plain => "plain",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "bwrap" => Self::Bwrap,
            "podman" => Self::Podman,
            "plain" => Self::Plain,
            _ => return None,
        })
    }
}
