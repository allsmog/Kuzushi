use super::*;
use crate::content_store::{ObjectKind, ObjectRef, MAX_CONTENT_OBJECT_BYTES};
use crate::identity::Blake3Hash;
use crate::workflow_attempts::TargetContentIdentity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PatchAttempt {
    pub attempt: usize,
    pub diff: String,
    pub status: PatchStatus,
    pub output: String,
}

/// Immutable source and detector binding captured when a patch is generated.
///
/// The binding is deliberately reference-only: detector input remains in the
/// canonical run artifact store and is checked against `detector_input_digest`
/// before re-verification replays it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PatchProvenance {
    pub source_commit: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub originating_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_input_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproducer: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_source_identity: Option<TargetContentIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_run_id: Option<String>,
}

impl PatchProvenance {
    /// Compute the canonical digest stored beside detector provenance.
    /// Consumers that construct or inspect a persisted `PatchResult` can use
    /// this to bind the exact canonical `input.json` bytes without duplicating
    /// the domain separator.
    pub fn digest_detector_input(input: &[u8]) -> String {
        crate::identity::hash_parts("kuzushi.patch.detector-input.v1", &[input]).to_string()
    }

    /// Reject partially-bound candidates at every selection and Apply edge.
    /// Optional fields remain serde-compatible for legacy records, but a new
    /// application must have complete source, target, run, and detector
    /// provenance.
    pub fn ensure_complete_for_apply(&self) -> Result<()> {
        ensure_nonempty_binding("generation commit", &self.source_commit)?;
        ensure_nonempty_binding("target identity", &self.target)?;
        ensure_optional_binding("originating run", self.originating_run_id.as_deref())?;
        ensure_optional_binding("detector tool", self.detector_tool.as_deref())?;
        ensure_optional_binding("detector run", self.detector_run_id.as_deref())?;
        ensure_optional_binding(
            "detector input digest",
            self.detector_input_digest.as_deref(),
        )
    }
}

fn ensure_optional_binding(label: &str, value: Option<&str>) -> Result<()> {
    ensure_nonempty_binding(label, value.unwrap_or_default())
}

fn ensure_nonempty_binding(label: &str, value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.trim().is_empty(),
        "patch provenance has no {label}; regenerate it"
    );
    Ok(())
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
    /// Missing only on legacy patch attempts. Legacy candidates remain
    /// viewable, but cannot cross the source-bound Apply gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<PatchProvenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Minimal durable patch-attempt truth for presentation and status surfaces.
///
/// This intentionally omits the diff and validator payload so read-only
/// callers do not need to open the content-object store merely to display the
/// latest synthesis state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchAttemptSummary {
    pub patch_run_id: String,
    pub status: PatchStatus,
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
            "provenance": null,
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_verification_provenance"
    )]
    pub provenance: Option<VerificationProvenance>,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationProvenance {
    pub source_identity: TargetContentIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproducer: Option<ObjectRef>,
}

impl VerificationProvenance {
    pub fn validate(&self) -> Result<()> {
        match &self.source_identity {
            TargetContentIdentity::IndexedSnapshot {
                snapshot_hash,
                tree_hash,
            } => {
                Blake3Hash::new(snapshot_hash.as_str().to_string())?;
                if let Some(tree_hash) = tree_hash {
                    Blake3Hash::new(tree_hash.as_str().to_string())?;
                }
            }
            TargetContentIdentity::CleanGitCommit { commit } => {
                anyhow::ensure!(!commit.as_str().trim().is_empty(), "source commit is empty");
            }
            TargetContentIdentity::Unavailable { reason } => {
                anyhow::ensure!(
                    !reason.as_str().trim().is_empty(),
                    "source identity unavailable reason is empty"
                );
            }
        }
        if let Some(reproducer) = &self.reproducer {
            anyhow::ensure!(
                reproducer.kind == ObjectKind::ProofSnapshot,
                "verification reproducer is not a proof snapshot"
            );
            Blake3Hash::new(reproducer.hash.as_str().to_string())?;
            anyhow::ensure!(
                reproducer.size_bytes <= MAX_CONTENT_OBJECT_BYTES,
                "verification reproducer exceeds the CAS object limit"
            );
        }
        Ok(())
    }
}

fn deserialize_verification_provenance<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<VerificationProvenance>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let provenance = Option::<VerificationProvenance>::deserialize(deserializer)?;
    if let Some(provenance) = &provenance {
        provenance.validate().map_err(serde::de::Error::custom)?;
    }
    Ok(provenance)
}

impl PersistedVerification {
    pub fn is_model_assessment(&self) -> bool {
        self.backend == PersistedSandboxBackend::Model
    }

    pub fn is_empirically_verified(&self) -> bool {
        self.backend == PersistedSandboxBackend::Bwrap
            && self.proof_verdict == PersistedProofVerdict::Exploited
            && self.provenance.as_ref().is_some_and(|provenance| {
                provenance.source_identity.permits_cross_attempt_reuse()
                    && provenance.reproducer.is_some()
                    && provenance.validate().is_ok()
            })
    }

    pub fn has_terminal_runtime_verification(&self) -> bool {
        !self.is_model_assessment() && self.proof_verdict != PersistedProofVerdict::NotAttempted
    }

    pub fn validate_for_persistence(&self) -> Result<()> {
        if self.is_model_assessment() {
            anyhow::ensure!(
                self.proof_verdict == PersistedProofVerdict::NotAttempted,
                "model assessments cannot persist a runtime proof verdict"
            );
            anyhow::ensure!(
                self.proof_level <= 3,
                "model assessment proof level exceeds the static review ceiling"
            );
        }
        Ok(())
    }

    /// A proof outcome belongs to the current discovery generation only when
    /// both canonical run references are present and the verified scan id
    /// exactly matches the finding's current scan id. Legacy or stale proof is
    /// still displayable, but cannot advance workflow reality.
    pub fn is_current_for_scan(&self, current_scan_id: Option<&str>) -> bool {
        let has_verification_run = self
            .verification_run_id
            .as_deref()
            .is_some_and(|run_id| !run_id.trim().is_empty());
        has_verification_run
            && self
                .verified_scan_id
                .as_deref()
                .filter(|scan_id| !scan_id.trim().is_empty())
                .zip(current_scan_id.filter(|scan_id| !scan_id.trim().is_empty()))
                .is_some_and(|(verified, current)| verified == current)
    }
}

#[cfg(test)]
mod verification_generation_tests {
    use super::*;

    fn verification(run_id: Option<&str>, scan_id: Option<&str>) -> PersistedVerification {
        PersistedVerification {
            proof_level: 3,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Plain,
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 1,
            cost_usd: 0.0,
            notes: Vec::new(),
            verification_run_id: run_id.map(str::to_string),
            verified_scan_id: scan_id.map(str::to_string),
            provenance: None,
            created_at: "1".to_string(),
        }
    }

    #[test]
    fn current_generation_requires_both_exact_run_references() {
        assert!(verification(Some("verify-2"), Some("scan-2")).is_current_for_scan(Some("scan-2")));
        assert!(!verification(Some("verify-1"), Some("scan-1")).is_current_for_scan(Some("scan-2")));
        assert!(!verification(None, Some("scan-2")).is_current_for_scan(Some("scan-2")));
        assert!(!verification(Some("verify-2"), None).is_current_for_scan(Some("scan-2")));
    }

    #[test]
    fn model_assessments_never_have_runtime_authority() {
        let mut record = verification(Some("verify-2"), Some("scan-2"));
        record.backend = PersistedSandboxBackend::Model;

        assert!(record.is_model_assessment());
        assert!(!record.is_empirically_verified());
        assert!(!record.has_terminal_runtime_verification());
        assert!(record.validate_for_persistence().is_err());

        record.proof_verdict = PersistedProofVerdict::NotAttempted;
        assert!(record.validate_for_persistence().is_ok());
    }

    #[test]
    fn legacy_verification_without_provenance_deserializes() {
        let value = serde_json::json!({
            "proofLevel": 1,
            "proofVerdict": "not_attempted",
            "backend": "plain",
            "durationMs": 0,
            "costUsd": 0.0,
            "notes": [],
            "createdAt": "legacy"
        });

        let verification: PersistedVerification = serde_json::from_value(value).unwrap();

        assert!(verification.provenance.is_none());
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PersistedProofVerdict {
    NotAttempted,
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
            Self::NotAttempted => "not_attempted",
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
            "not_attempted" => Self::NotAttempted,
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
    Model,
}

impl PersistedSandboxBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bwrap => "bwrap",
            Self::Podman => "podman",
            Self::Plain => "plain",
            Self::Model => "model",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "bwrap" => Self::Bwrap,
            "podman" => Self::Podman,
            "plain" => Self::Plain,
            "model" => Self::Model,
            _ => return None,
        })
    }
}
