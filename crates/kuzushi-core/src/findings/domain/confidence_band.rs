use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Canonical confidence band. Prompts request a band (high/medium/low) rather
/// than a raw float; the ingestion layer maps the band to a numeric midpoint so
/// aggregation stays a Rust concern, not a model-invented probability.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
}

impl ConfidenceBand {
    /// Default numeric midpoint for the band, used when a downstream consumer
    /// needs a scalar 0.0..=1.0 confidence.
    pub fn midpoint(self) -> f32 {
        match self {
            Self::High => 0.85,
            Self::Medium => 0.60,
            Self::Low => 0.25,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Bucket a numeric confidence back into a band. Mirrors [`midpoint`] so a
    /// round-trip through numeric storage recovers a sensible band.
    pub fn from_score(score: f32) -> Self {
        if score >= 0.73 {
            Self::High
        } else if score >= 0.43 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

impl TryFrom<&str> for ConfidenceBand {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "high" => Ok(Self::High),
            "medium" | "med" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            other => anyhow::bail!("unknown confidence band {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bands_map_to_documented_midpoints() {
        assert!((ConfidenceBand::High.midpoint() - 0.85).abs() < 1e-6);
        assert!((ConfidenceBand::Medium.midpoint() - 0.60).abs() < 1e-6);
        assert!((ConfidenceBand::Low.midpoint() - 0.25).abs() < 1e-6);
    }

    #[test]
    fn parses_upper_and_lower_case_labels() {
        assert_eq!(
            ConfidenceBand::try_from("HIGH").unwrap(),
            ConfidenceBand::High
        );
        assert_eq!(
            ConfidenceBand::try_from("medium").unwrap(),
            ConfidenceBand::Medium
        );
        assert!(ConfidenceBand::try_from("bogus").is_err());
    }

    #[test]
    fn score_round_trips_through_band() {
        assert_eq!(ConfidenceBand::from_score(0.85), ConfidenceBand::High);
        assert_eq!(ConfidenceBand::from_score(0.60), ConfidenceBand::Medium);
        assert_eq!(ConfidenceBand::from_score(0.25), ConfidenceBand::Low);
    }
}
