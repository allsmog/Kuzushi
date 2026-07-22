use super::*;

pub(crate) fn build_triage_outcome(
    analysis: &VulnAnalysis,
    outcome: &AgentLoopOutcome,
) -> TriageOutcome {
    // Symmetric thresholds: a confident "false positive" verdict (the model
    // found an upstream guard) is just as valuable as a confident "true
    // positive" verdict. The previous 0.7 false-positive threshold was an
    // anti-bias hedge that systematically pushed evidence-backed
    // false-positive calls to needs_review — particularly bad in the
    // synthesis-fallback path, where confidence is intentionally capped.
    let verdict = match (analysis.triggerable, analysis.confidence) {
        (true, c) if c >= 0.5 => TriageVerdict::TruePositive,
        (false, c) if c >= 0.5 => TriageVerdict::FalsePositive,
        _ => TriageVerdict::NeedsReview,
    };
    let rationale = if outcome.truncated {
        format!(
            "[deep-auditor truncated at {} steps] {}",
            outcome.steps_used, analysis.rationale
        )
    } else {
        analysis.rationale.clone()
    };
    TriageOutcome {
        verdict,
        confidence: analysis.confidence,
        rationale,
        // Refute reason only accompanies a refuting verdict; a model that
        // emits one alongside triggerable=true is discarded as noise.
        refute_reason: analysis
            .refute_reason
            .filter(|_| verdict == TriageVerdict::FalsePositive),
        first_link: analysis
            .first_link
            .as_deref()
            .map(str::trim)
            .filter(|link| !link.is_empty())
            .map(str::to_string),
        cost_usd: outcome.cost_usd,
        cost_usd_exact: outcome.cost_usd_exact,
    }
}
