use super::*;

pub(crate) fn build_variant_lift_prompt(finding: &Finding) -> String {
    let finding_json = serde_json::to_string_pretty(finding).unwrap_or_else(|_| "{}".to_string());
    [
        "Extract a portable semantic signature for this confirmed vulnerability.",
        "Identify the attacker-controlled source, dangerous sink, missing guard, affected languages, and grep-friendly keywords.",
        "Use repository source evidence; do not speculate.",
        "",
        "Finding JSON:",
        &finding_json,
    ]
    .join("\n")
}

pub(crate) fn build_variant_hunt_prompt(
    finding: &Finding,
    include_vendored: bool,
    vendor_paths: &[String],
) -> String {
    let triage = finding
        .triage
        .as_ref()
        .map(|triage| {
            format!(
                "Verdict: {}\nConfidence: {:.2}\nRationale: {}",
                triage.verdict.as_str(),
                triage.confidence,
                triage.rationale
            )
        })
        .unwrap_or_else(|| "Verdict: none".to_string());
    let vendor_scope = if include_vendored {
        format!(
            "Extend search scope to vendored and third-party code under: {}.",
            vendor_paths
                .iter()
                .map(|path| format!("{path}/"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        "Restrict search to first-party source; skip vendored and third-party directories."
            .to_string()
    };
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
        "Triage assessment:",
        &triage,
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
) -> String {
    let advisory = record
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
        });
    let trimmed = if patch_text.len() > 18_000 {
        format!("{}\n... [truncated]", &patch_text[..18_000])
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
