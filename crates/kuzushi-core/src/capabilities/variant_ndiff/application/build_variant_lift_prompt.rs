use super::*;
use crate::findings::ReviewConfirmation;

pub(crate) fn build_variant_lift_prompt(
    finding: &Finding,
    confirmation: &ReviewConfirmation,
) -> String {
    let finding_json = serde_json::to_string_pretty(finding).unwrap_or_else(|_| "{}".to_string());
    let (heading, assessment) = confirmation_assessment(confirmation);
    [
        "Extract a portable semantic signature for this confirmed vulnerability.",
        "Identify the attacker-controlled source, dangerous sink, missing guard, affected languages, and grep-friendly keywords.",
        "Use repository source evidence; do not speculate.",
        "Return a draft only. It is not an accepted lesson and must not start further discovery or change context.",
        heading,
        &assessment,
        "",
        "Finding JSON:",
        &finding_json,
    ]
    .join("\n")
}

/// The evidence that confirmed the finding, headed by its real source so a
/// reviewer's decision is never presented to the model as automated triage.
fn confirmation_assessment(confirmation: &ReviewConfirmation) -> (&'static str, String) {
    match confirmation {
        ReviewConfirmation::AutomatedTriage(triage) => (
            "Triage assessment:",
            format!(
                "Verdict: {}\nConfidence: {:.2}\nRationale: {}",
                triage.verdict.as_str(),
                triage.confidence,
                triage.rationale
            ),
        ),
        ReviewConfirmation::ReviewDecision(decision) => (
            "Review decision:",
            format!(
                "Verdict: {}\nAuthor: {}\nConfidence: {:.2}\nRationale: {}",
                decision.verdict.as_str(),
                decision.author.as_str(),
                decision.confidence,
                decision.rationale
            ),
        ),
    }
}

fn variant_hunt_vendor_scope(include_vendored: bool, vendor_paths: &[String]) -> String {
    if !include_vendored {
        return "Restrict search to first-party source; skip vendored and third-party directories."
            .to_string();
    }
    let paths = vendor_paths
        .iter()
        .map(|path| format!("{path}/"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("Extend search scope to vendored and third-party code under: {paths}.")
}

pub(crate) fn build_variant_hunt_prompt(
    finding: &Finding,
    confirmation: &ReviewConfirmation,
    include_vendored: bool,
    vendor_paths: &[String],
) -> String {
    let (assessment_heading, assessment) = confirmation_assessment(confirmation);
    let vendor_scope = variant_hunt_vendor_scope(include_vendored, vendor_paths);
    [
        "A confirmed vulnerability has been found. Search for other locations with the same vulnerability pattern.",
        "",
        "Confirmed vulnerability:",
        &format!(
            "Tool: {}\nRule: {}\nFile: {}:{}\nSeverity: {}\nMessage: {}",
            finding.tool,
            finding.rule_id,
            finding.file_path,
            finding.start_line,
            finding.severity.as_str(),
            finding.message
        ),
        "",
        assessment_heading,
        &assessment,
        "",
        "Methodology:",
        "1. Read the original vulnerable code and extract source, sink, and missing guard.",
        "2. Search for the same sink and missing guard elsewhere.",
        "3. Skip the original file:line.",
        "4. Return only verified HIGH or MEDIUM confidence variants.",
        &vendor_scope,
    ]
    .join("\n")
}

pub(crate) fn build_ndiff_fix_pattern_prompt(
    record: Option<&CveRecord>,
    patch_text: &str,
    max_source_bytes: usize,
) -> String {
    let advisory = ndiff_advisory_context(record);
    let prefix = ndiff_diff_prefix(patch_text, max_source_bytes);
    let trimmed = if prefix.len() < patch_text.len() {
        format!("{prefix}\n... [truncated]")
    } else {
        patch_text.to_string()
    };
    [
        "Extract a portable fix-shape signature from this CVE patch.",
        "Describe what the patch added, the vulnerable pre-patch shape, relevant CWEs, languages, keywords, and a detection query.",
        "",
        "Advisory:",
        &advisory,
        "",
        "Patch diff:",
        "```diff",
        &trimmed,
        "```",
    ]
    .join("\n")
}

pub(crate) fn ndiff_diff_prefix(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn ndiff_advisory_context(record: Option<&CveRecord>) -> String {
    record
        .map(|record| {
            format!(
                "ID: {}\nCWEs: {}\n\n{}",
                record.id,
                if record.cwes.is_empty() {
                    "(none listed)".to_string()
                } else {
                    record.cwes.join(", ")
                },
                record.description.trim()
            )
        })
        .unwrap_or_else(|| {
            "(No structured advisory record supplied; infer from the patch.)".to_string()
        })
}
