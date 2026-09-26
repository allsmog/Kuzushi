use super::*;

pub(crate) fn build_triage_outcome(
    analysis: &VulnAnalysis,
    outcome: &AgentLoopOutcome,
) -> TriageOutcome {
    let verdict = supported_verdict(analysis);
    let rationale = assessment_rationale(analysis);
    let rationale = if outcome.truncated {
        format!(
            "[deep-auditor truncated at {} steps] {}",
            outcome.steps_used, rationale
        )
    } else {
        rationale
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
        // Tool-loop steps carry no per-call token estimate yet.
        estimated_cost_usd: None,
    }
}

fn supported_verdict(analysis: &VulnAnalysis) -> TriageVerdict {
    if missing_refutation_call_path(analysis) {
        return TriageVerdict::NeedsReview;
    }
    match (analysis.triggerable, analysis.confidence) {
        (Some(true), c) if c >= 0.5 => TriageVerdict::TruePositive,
        (Some(false), c) if c >= 0.5 => TriageVerdict::FalsePositive,
        _ => TriageVerdict::NeedsReview,
    }
}

fn missing_refutation_call_path(analysis: &VulnAnalysis) -> bool {
    if analysis.triggerable != Some(false) {
        return false;
    }
    if analysis.refute_reason != Some(crate::findings::RefuteReason::ImplausibleTrigger) {
        return false;
    }
    analysis
        .first_link
        .as_deref()
        .is_none_or(|link| link.trim().is_empty())
}

fn assessment_rationale(analysis: &VulnAnalysis) -> String {
    if missing_refutation_call_path(analysis) {
        return format!(
            "[needs review: no inspected call path supports the implausible-trigger refutation] {}",
            analysis.rationale
        );
    }
    analysis.rationale.clone()
}

#[cfg(test)]
mod tests;
