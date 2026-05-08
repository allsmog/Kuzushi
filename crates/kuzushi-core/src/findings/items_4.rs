use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticProofState {
    SignalOnly,
    CodeCited,
    SourceSinkLinked,
    SanitizerChecked,
    StaticallyConfirmed,
    StaticallyRejected,
    NeedsRuntimeEvidence,
}

impl StaticProofState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignalOnly => "signal_only",
            Self::CodeCited => "code_cited",
            Self::SourceSinkLinked => "source_sink_linked",
            Self::SanitizerChecked => "sanitizer_checked",
            Self::StaticallyConfirmed => "statically_confirmed",
            Self::StaticallyRejected => "statically_rejected",
            Self::NeedsRuntimeEvidence => "needs_runtime_evidence",
        }
    }

    pub fn is_static_terminal_state(self) -> bool {
        matches!(
            self,
            Self::StaticallyConfirmed | Self::StaticallyRejected | Self::NeedsRuntimeEvidence
        )
    }
}

impl TryFrom<&str> for StaticProofState {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value.trim() {
            "signal_only" | "signal-only" | "signal" => Ok(Self::SignalOnly),
            "code_cited" | "code-cited" | "cited" => Ok(Self::CodeCited),
            "source_sink_linked" | "source-sink-linked" | "linked" => Ok(Self::SourceSinkLinked),
            "sanitizer_checked" | "sanitizer-checked" | "sanitizer" => Ok(Self::SanitizerChecked),
            "statically_confirmed" | "statically-confirmed" => Ok(Self::StaticallyConfirmed),
            "statically_rejected" | "statically-rejected" => Ok(Self::StaticallyRejected),
            "needs_runtime_evidence" | "needs-runtime-evidence" | "needs_runtime" => {
                Ok(Self::NeedsRuntimeEvidence)
            }
            "execution_confirmed"
            | "runtime_confirmed"
            | "dynamic_confirmed"
            | "exploit_confirmed"
            | "poc_confirmed" => {
                anyhow::bail!("execution proof state {value:?} is not valid static proof")
            }
            other => anyhow::bail!("unknown static proof state {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TriageOutcome {
    pub verdict: TriageVerdict,
    pub confidence: f32,
    pub rationale: String,
    /// USD cost of the LLM call that produced this verdict. Populated
    /// by providers that surface usage (e.g. `AnthropicOAuthRuntime`
    /// reads `usage.input_tokens` / `usage.output_tokens` and applies
    /// the per-model rate). Defaults to `0.0`. Drives `triage:run`'s
    /// in-process cost cap.
    #[serde(default)]
    pub cost_usd: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PatchStatus {
    ApplyFailed,
    BuildFailed,
    StillVulnerable,
    TestsFailed,
    Sound,
    Verified,
    Unknown,
}

impl PatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApplyFailed => "APPLY_FAILED",
            Self::BuildFailed => "BUILD_FAILED",
            Self::StillVulnerable => "STILL_VULNERABLE",
            Self::TestsFailed => "TESTS_FAILED",
            Self::Sound => "SOUND",
            Self::Verified => "VERIFIED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl TryFrom<&str> for PatchStatus {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "APPLY_FAILED" => Ok(Self::ApplyFailed),
            "BUILD_FAILED" => Ok(Self::BuildFailed),
            "STILL_VULNERABLE" => Ok(Self::StillVulnerable),
            "TESTS_FAILED" => Ok(Self::TestsFailed),
            "SOUND" => Ok(Self::Sound),
            "VERIFIED" => Ok(Self::Verified),
            "UNKNOWN" => Ok(Self::Unknown),
            other => anyhow::bail!("unknown patch status {other:?}"),
        }
    }
}
