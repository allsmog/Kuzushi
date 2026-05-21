use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
        STATIC_PROOF_STATE_LABELS
            .iter()
            .find_map(|(state, label)| (*state == self).then_some(*label))
            .unwrap_or("signal_only")
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
        let normalized = value.trim();
        if is_runtime_proof_state(normalized) {
            anyhow::bail!("execution proof state {value:?} is not valid static proof");
        }
        STATIC_PROOF_STATE_ALIASES
            .iter()
            .find_map(|(alias, state)| (*alias == normalized).then_some(*state))
            .with_context(|| format!("unknown static proof state {normalized:?}"))
    }
}

const STATIC_PROOF_STATE_LABELS: &[(StaticProofState, &str)] = &[
    (StaticProofState::SignalOnly, "signal_only"),
    (StaticProofState::CodeCited, "code_cited"),
    (StaticProofState::SourceSinkLinked, "source_sink_linked"),
    (StaticProofState::SanitizerChecked, "sanitizer_checked"),
    (
        StaticProofState::StaticallyConfirmed,
        "statically_confirmed",
    ),
    (StaticProofState::StaticallyRejected, "statically_rejected"),
    (
        StaticProofState::NeedsRuntimeEvidence,
        "needs_runtime_evidence",
    ),
];

const STATIC_PROOF_STATE_ALIASES: &[(&str, StaticProofState)] = &[
    ("signal_only", StaticProofState::SignalOnly),
    ("signal-only", StaticProofState::SignalOnly),
    ("signal", StaticProofState::SignalOnly),
    ("code_cited", StaticProofState::CodeCited),
    ("code-cited", StaticProofState::CodeCited),
    ("cited", StaticProofState::CodeCited),
    ("source_sink_linked", StaticProofState::SourceSinkLinked),
    ("source-sink-linked", StaticProofState::SourceSinkLinked),
    ("linked", StaticProofState::SourceSinkLinked),
    ("sanitizer_checked", StaticProofState::SanitizerChecked),
    ("sanitizer-checked", StaticProofState::SanitizerChecked),
    ("sanitizer", StaticProofState::SanitizerChecked),
    (
        "statically_confirmed",
        StaticProofState::StaticallyConfirmed,
    ),
    (
        "statically-confirmed",
        StaticProofState::StaticallyConfirmed,
    ),
    ("statically_rejected", StaticProofState::StaticallyRejected),
    ("statically-rejected", StaticProofState::StaticallyRejected),
    (
        "needs_runtime_evidence",
        StaticProofState::NeedsRuntimeEvidence,
    ),
    (
        "needs-runtime-evidence",
        StaticProofState::NeedsRuntimeEvidence,
    ),
    ("needs_runtime", StaticProofState::NeedsRuntimeEvidence),
];

pub(crate) fn is_runtime_proof_state(state: &str) -> bool {
    matches!(
        state.trim(),
        "execution_confirmed"
            | "runtime_confirmed"
            | "dynamic_confirmed"
            | "exploit_confirmed"
            | "poc_confirmed"
            | "runtime_reviewed"
            | "execution_attempted"
            | "execution_rejected"
    )
}
