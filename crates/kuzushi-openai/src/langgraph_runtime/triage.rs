use anyhow::Result;
use kuzushi_core::prompts::{assemble_system_prompt, FALSE_POSITIVE_TAXONOMY};
use kuzushi_core::{Finding, TriageOutcome};

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

Assign confidence by evidence, not by how sure you feel. Return only JSON matching:
{\"verdict\":\"true_positive|false_positive|needs_review\",\"confidence\":0.0-1.0,\"rationale\":\"short cited-evidence reason\"}.
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
