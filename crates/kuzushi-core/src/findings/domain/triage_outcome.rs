use super::TriageVerdict;
use serde::{Deserialize, Serialize};

/// Closed refutation vocabulary for false-positive verdicts (reference
/// triage-skill parity). Unknown model output parses to `Unspecified`
/// instead of failing the whole outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefuteReason {
    DoesntExist,
    AlreadyHandled,
    ImplausibleTrigger,
    IntentionalBehavior,
    MisreadCode,
    Duplicate,
    NotActionable,
    #[serde(other)]
    Unspecified,
}

impl RefuteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoesntExist => "doesnt_exist",
            Self::AlreadyHandled => "already_handled",
            Self::ImplausibleTrigger => "implausible_trigger",
            Self::IntentionalBehavior => "intentional_behavior",
            Self::MisreadCode => "misread_code",
            Self::Duplicate => "duplicate",
            Self::NotActionable => "not_actionable",
            Self::Unspecified => "unspecified",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TriageOutcome {
    pub verdict: TriageVerdict,
    pub confidence: f32,
    pub rationale: String,
    /// Enum-coded refutation reason on false-positive verdicts. `None` on
    /// true-positive/needs-review verdicts and legacy rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refute_reason: Option<RefuteReason>,
    /// `file:line` of the first call site actually read while tracing
    /// reachability (populated by code-reading triage strategies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_link: Option<String>,
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
    /// Rationale with the structured annotations folded in as stable
    /// `key=value` prefixes. The review-decision event payload and its
    /// projection carry only a rationale string, so this is how
    /// refute-reason and first-link survive event replay.
    pub fn rationale_with_annotations(&self) -> String {
        let mut prefixes = Vec::new();
        if let Some(reason) = self.refute_reason {
            prefixes.push(format!("refute_reason={}", reason.as_str()));
        }
        if let Some(first_link) = self
            .first_link
            .as_deref()
            .map(str::trim)
            .filter(|link| !link.is_empty())
        {
            prefixes.push(format!("first_link={first_link}"));
        }
        if prefixes.is_empty() {
            return self.rationale.clone();
        }
        format!("[{}] {}", prefixes.join("; "), self.rationale)
    }

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
            refute_reason: None,
            first_link: None,
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
    fn annotations_fold_into_the_rationale_and_legacy_shape_is_preserved() {
        let annotated = TriageOutcome {
            verdict: TriageVerdict::FalsePositive,
            rationale: "guard at auth.c:68 blocks the flow".to_string(),
            refute_reason: Some(RefuteReason::AlreadyHandled),
            first_link: Some("src/auth.c:112".to_string()),
            ..Default::default()
        };
        assert_eq!(
            annotated.rationale_with_annotations(),
            "[refute_reason=already_handled; first_link=src/auth.c:112] guard at auth.c:68 blocks the flow"
        );
        // Legacy shape: no new keys serialized when unset.
        let legacy = serde_json::to_value(TriageOutcome::default()).unwrap();
        assert!(legacy.get("refute_reason").is_none());
        assert!(legacy.get("first_link").is_none());
    }

    #[test]
    fn unknown_refute_reason_parses_to_unspecified() {
        let outcome: TriageOutcome = serde_json::from_value(serde_json::json!({
            "verdict": "false_positive",
            "confidence": 0.8,
            "rationale": "r",
            "refute_reason": "some_new_reason"
        }))
        .unwrap();
        assert_eq!(outcome.refute_reason, Some(RefuteReason::Unspecified));
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
