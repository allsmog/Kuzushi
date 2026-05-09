use super::*;

pub(crate) fn build_triage_outcome(
    analysis: &VulnAnalysis,
    outcome: &AgentLoopOutcome,
) -> TriageOutcome {
    let verdict = match (analysis.triggerable, analysis.confidence) {
        (true, c) if c >= 0.5 => TriageVerdict::TruePositive,
        (false, c) if c >= 0.7 => TriageVerdict::FalsePositive,
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
        cost_usd: outcome.cost_usd,
    }
}
