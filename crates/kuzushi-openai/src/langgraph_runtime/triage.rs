use anyhow::Result;
use kuzushi_core::{Finding, TriageOutcome, TriageVerdict};

pub(crate) const TRIAGE_SYSTEM_PROMPT: &str = r#"You are Kuzushi's security triage agent.
Return only JSON matching:
{"verdict":"true_positive|false_positive|needs_review","confidence":0.0-1.0,"rationale":"short evidence-based reason"}."#;

pub(crate) fn triage_prompt(finding: &Finding, template: Option<&str>) -> Result<String> {
    crate::triage_prompt::compact_triage_prompt(finding, template)
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
