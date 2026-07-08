use serde::{Deserialize, Serialize};

/// Coarse, operator-facing confidence in a finding, derived from the SAME state
/// that governs verification (static proof ladder + runtime verification verdict
/// + triage verdict + suppression). This is a *proof/verification* axis, distinct
/// from `TriageOutcome.confidence` (the model's self-reported score) and from
/// `Severity` (impact).
///
/// Declaration order is high-confidence-first so `Ord`/`rank()` sort `Confirmed`
/// most-significant and `Dismissed` least. The classifier that maps a `Finding`
/// onto this enum (`ProofConfidence::classify`) lives with the proof ladder
/// (`presentation::detail`) so the chip can never disagree with the ladder /
/// lifecycle status.
///
/// `classify` is patch-blind: `Finding` carries no patch field, so it always
/// resolves the ladder with `latest_patch: None`. In practice `Confirmed` here
/// means *runtime-exploited*, not "runtime-exploited or a verified patch" — the
/// ladder's `Patched` rung (which does fold into `Confirmed`) is only reachable
/// from callers that thread real `PatchResult` data in explicitly, such as
/// `proof_ladder_state` in finding-detail rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofConfidence {
    /// Runtime-exploited. (The ladder also folds a sound/verified patch into
    /// this rung, but `classify` never sees patch data — see the type-level
    /// doc comment.)
    Confirmed,
    /// Static evidence links the finding (code-cited / source-sink / sanitizer /
    /// statically-confirmed) but no runtime proof is recorded.
    Likely,
    /// Signal-only, needs-runtime, or nothing recorded (default).
    #[default]
    Unverified,
    /// Statically rejected, triaged false-positive / by-design, or suppressed.
    Dismissed,
}

impl ProofConfidence {
    /// Machine-readable snake_case token for exports/filters.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Likely => "likely",
            Self::Unverified => "unverified",
            Self::Dismissed => "dismissed",
        }
    }

    /// Operator-facing chip label. Strong bands are uppercased for prominence;
    /// weak bands stay muted/lowercase, matching the repo's signifier convention.
    pub fn label(self) -> &'static str {
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::Likely => "LIKELY",
            Self::Unverified => "unverified",
            Self::Dismissed => "dismissed",
        }
    }

    /// Sort rank: 0 = most significant (`Confirmed`). Ascending sort puts
    /// `Confirmed` first, matching declaration order.
    pub fn rank(self) -> u8 {
        self as u8
    }
}

impl TryFrom<&str> for ProofConfidence {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match normalize(value).as_str() {
            "confirmed" | "verified" | "exploited" | "runtimeverified" => Ok(Self::Confirmed),
            "likely" | "supported" | "static" | "staticsupported" | "pathlinked" => {
                Ok(Self::Likely)
            }
            "unverified" | "suspected" | "candidate" | "unknown" | "signal" => Ok(Self::Unverified),
            "dismissed" | "rejected" | "falsepositive" | "fp" | "suppressed" | "bydesign" => {
                Ok(Self::Dismissed)
            }
            other => anyhow::bail!("unknown proof confidence {other:?}"),
        }
    }
}

fn normalize(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(['_', '-', ' '], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_is_confirmed_first() {
        assert_eq!(ProofConfidence::Confirmed.rank(), 0);
        assert_eq!(ProofConfidence::Likely.rank(), 1);
        assert_eq!(ProofConfidence::Unverified.rank(), 2);
        assert_eq!(ProofConfidence::Dismissed.rank(), 3);
        assert!(ProofConfidence::Confirmed < ProofConfidence::Dismissed);
    }

    #[test]
    fn labels_and_tokens_are_stable() {
        assert_eq!(ProofConfidence::Confirmed.label(), "CONFIRMED");
        assert_eq!(ProofConfidence::Likely.label(), "LIKELY");
        assert_eq!(ProofConfidence::Unverified.label(), "unverified");
        assert_eq!(ProofConfidence::Dismissed.label(), "dismissed");
        assert_eq!(ProofConfidence::Confirmed.as_str(), "confirmed");
        assert_eq!(ProofConfidence::Dismissed.as_str(), "dismissed");
    }

    #[test]
    fn try_from_accepts_aliases_and_rejects_garbage() {
        assert_eq!(
            ProofConfidence::try_from("verified").unwrap(),
            ProofConfidence::Confirmed
        );
        assert_eq!(
            ProofConfidence::try_from("static-supported").unwrap(),
            ProofConfidence::Likely
        );
        assert_eq!(
            ProofConfidence::try_from("suspected").unwrap(),
            ProofConfidence::Unverified
        );
        assert_eq!(
            ProofConfidence::try_from("false_positive").unwrap(),
            ProofConfidence::Dismissed
        );
        assert!(ProofConfidence::try_from("banana").is_err());
    }

    #[test]
    fn as_str_round_trips_through_try_from() {
        for band in [
            ProofConfidence::Confirmed,
            ProofConfidence::Likely,
            ProofConfidence::Unverified,
            ProofConfidence::Dismissed,
        ] {
            assert_eq!(ProofConfidence::try_from(band.as_str()).unwrap(), band);
        }
    }
}
