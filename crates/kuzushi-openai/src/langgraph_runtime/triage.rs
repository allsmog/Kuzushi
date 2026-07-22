use anyhow::Result;
use kuzushi_core::prompts::{assemble_system_prompt, FALSE_POSITIVE_TAXONOMY};
use kuzushi_core::{ConfidenceBand, Finding, TriageOutcome};
use serde_json::Value;

/// Map a string `confidence` band (e.g. `"high"`) emitted by the model to its
/// canonical numeric midpoint in place, so a `TriageOutcome` with an `f32`
/// confidence still deserializes. Numeric confidences are left untouched.
pub(crate) fn normalize_triage_confidence(value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let Some(Value::String(band)) = object.get("confidence") else {
        return;
    };
    if let Ok(band) = ConfidenceBand::try_from(band.as_str()) {
        object.insert("confidence".to_string(), serde_json::json!(band.midpoint()));
    }
}

const TRIAGE_HEADER: &str =
    "You are Kuzushi's security triage agent. Assume the finding is a false positive until \
concrete cited code proves otherwise. Scanner findings are often false positives because \
scanner context misses middleware, framework guards, centralized validators, sanitizers, \
privilege gates, runtime reachability, and type/length constraints.

Your job is not rediscovery. Your job is to verify or falsify the supplied claim.";

const TRIAGE_VERDICT_RULES: &str = "Verdict rules:
- true_positive: cited code shows attacker-controlled input reaches a security-sensitive sink \
  with no effective guard, or with a guard that is bypassed by cited logic.
- false_positive: cited code shows no attacker control, unreachable code, a constant sink, \
  a decisive validator/sanitizer/guard, or intended privileged functionality.
- needs_review: evidence is incomplete, mixed, or requires runtime/context not available.

On false_positive, also set refute_reason to exactly one of: doesnt_exist, already_handled, \
implausible_trigger, intentional_behavior, misread_code, duplicate, not_actionable. On other \
verdicts set it null. When the supplied evidence names a caller/call-site you relied on for \
reachability, set first_link to that file:line; otherwise null — never invent one.

Assign confidence by evidence, not by how sure you feel. Return a confidence band \
(high/medium/low), not an invented numeric probability; the ingestion layer maps the band to a \
numeric midpoint. Return only JSON matching:
{\"verdict\":\"true_positive|false_positive|needs_review\",\"confidence\":\"high|medium|low\",\"rationale\":\"short cited-evidence reason\",\"refute_reason\":\"...|null\",\"first_link\":\"file:line|null\"}.
Do not include markdown fences, prose, or schema text.";

pub(crate) fn triage_system_prompt() -> String {
    assemble_system_prompt(
        TRIAGE_HEADER,
        &[FALSE_POSITIVE_TAXONOMY, TRIAGE_VERDICT_RULES],
    )
}

pub(crate) fn triage_prompt(finding: &Finding, template: Option<&str>) -> Result<String> {
    crate::triage_prompt::compact_triage_prompt(finding, template)
}

pub(crate) fn clamp_outcome(mut outcome: TriageOutcome) -> TriageOutcome {
    outcome.confidence = outcome.confidence.clamp(0.0, 1.0);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_prompt_requests_a_band_and_is_false_positive_first() {
        let prompt = triage_system_prompt();
        assert!(prompt.contains("Assume the finding is a false positive"));
        assert!(prompt.contains("Return a confidence band"));
        assert!(prompt.contains("false-DISMISSAL traps"));
    }

    #[test]
    fn string_confidence_band_maps_to_numeric_midpoint() {
        let mut value = serde_json::json!({
            "verdict": "true_positive",
            "confidence": "high",
            "rationale": "cited sink"
        });
        normalize_triage_confidence(&mut value);
        assert_eq!(value["confidence"], serde_json::json!(0.85_f32));
    }

    #[test]
    fn numeric_confidence_is_left_untouched() {
        let mut value = serde_json::json!({"confidence": 0.42});
        normalize_triage_confidence(&mut value);
        assert_eq!(value["confidence"], serde_json::json!(0.42));
    }
}
