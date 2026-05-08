use anyhow::{Context, Result};
use kuzushi_core::{TriageOutcome, TriageVerdict};

pub(crate) const TRIAGE_SYSTEM_PROMPT: &str = r#"You are Kuzushi's security triage agent.
Return only JSON matching:
{"verdict":"true_positive|false_positive|needs_review","confidence":0.0-1.0,"rationale":"short evidence-based reason"}."#;

pub(crate) fn triage_prompt(
    finding: &kuzushi_core::Finding,
    template: Option<&str>,
) -> Result<String> {
    let json = serde_json::to_string_pretty(finding).context("Could not serialize finding")?;
    let prefix = template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(
        "Triage this SAST finding. Be conservative; use needs_review when evidence is incomplete.",
    );
    Ok(format!("{prefix}\n\nFinding JSON:\n{json}"))
}

pub(crate) fn clamp_outcome(mut outcome: TriageOutcome) -> TriageOutcome {
    outcome.confidence = outcome.confidence.clamp(0.0, 1.0);
    outcome
}

pub(crate) fn fallback_triage_outcome(text: String) -> TriageOutcome {
    TriageOutcome {
        verdict: TriageVerdict::NeedsReview,
        confidence: 0.25,
        rationale: text,
        ..Default::default()
    }
}
