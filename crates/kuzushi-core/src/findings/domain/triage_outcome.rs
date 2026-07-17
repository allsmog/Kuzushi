use super::TriageVerdict;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// Whether `cost_usd` is the complete provider-reported charge. Legacy
    /// persisted outcomes default to exact because they predate the ability
    /// to represent unpriced provider calls; new runtime adapters overwrite
    /// this from `AgentQueryResponse::checked_cost_report`.
    #[serde(default = "default_cost_usd_exact", skip_serializing_if = "is_true")]
    pub cost_usd_exact: bool,
}

impl TriageOutcome {
    pub fn validate_cost(self) -> anyhow::Result<Self> {
        anyhow::ensure!(
            self.cost_usd.is_finite() && self.cost_usd >= 0.0,
            "triage outcome cost must be a finite non-negative USD amount, got {}",
            self.cost_usd
        );
        Ok(self)
    }
}

impl Default for TriageOutcome {
    fn default() -> Self {
        Self {
            verdict: TriageVerdict::default(),
            confidence: 0.0,
            rationale: String::new(),
            cost_usd: 0.0,
            cost_usd_exact: true,
        }
    }
}

const fn default_cost_usd_exact() -> bool {
    true
}

const fn is_true(value: &bool) -> bool {
    *value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_persisted_outcome_defaults_cost_to_exact() {
        let outcome: TriageOutcome = serde_json::from_value(serde_json::json!({
            "verdict": "needs_review",
            "confidence": 0.5,
            "rationale": "legacy",
            "cost_usd": 0.0
        }))
        .unwrap();

        assert_eq!(outcome.cost_usd, 0.0);
        assert!(outcome.cost_usd_exact);
    }

    #[test]
    fn unresolved_cost_exactness_round_trips_without_changing_legacy_shape() {
        let legacy = serde_json::to_value(TriageOutcome::default()).unwrap();
        assert!(legacy.get("cost_usd_exact").is_none());

        let unresolved = TriageOutcome {
            cost_usd_exact: false,
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(unresolved).unwrap()["cost_usd_exact"],
            serde_json::json!(false)
        );
    }
}
