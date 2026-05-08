use super::*;

pub(crate) fn variant_message(
    message: Option<&str>,
    rationale: Option<&str>,
    confidence: &str,
    cwes: &[String],
    fallback: &str,
) -> String {
    let mut output = message
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_string();
    if let Some(rationale) = rationale.map(str::trim).filter(|value| !value.is_empty()) {
        output.push_str("\nRationale: ");
        output.push_str(rationale);
    }
    output.push_str("\nConfidence: ");
    output.push_str(confidence.trim());
    if !cwes.is_empty() {
        output.push_str("\nCWE: ");
        output.push_str(&cwes.join(", "));
    }
    output
}

pub(crate) fn render_variant_hunt_output(
    original: &Finding,
    count: usize,
    include_vendored: bool,
    findings: &[Finding],
) -> String {
    let mut lines = vec![
        format!(
            "variant:hunt complete for {} ({}:{})",
            original.rule_id, original.file_path, original.start_line
        ),
        format!("  Variants found: {count}"),
        format!(
            "  Scope:          {}",
            if include_vendored {
                "repo + vendored"
            } else {
                "repo only"
            }
        ),
        "  Cost:           $0.0000".to_string(),
    ];
    if !findings.is_empty() {
        lines.push(String::new());
        lines.push("Top variants:".to_string());
        for finding in findings.iter().take(5) {
            lines.push(format!(
                "  - {}:{} ({}) - {}",
                finding.file_path,
                finding.start_line,
                finding.severity.as_str(),
                finding.title
            ));
        }
    }
    lines.join("\n")
}

pub(crate) fn render_ndiff_hunt_output(
    advisory_id: &str,
    count: usize,
    include_vendored: bool,
    findings: &[Finding],
) -> String {
    let mut lines = vec![
        format!("ndiff:hunt-variants complete ({advisory_id})"),
        format!("  Variants:   {count}"),
        format!(
            "  Scope:      {}",
            if include_vendored {
                "repo + vendored"
            } else {
                "repo only"
            }
        ),
        "  Cost:       $0.0000".to_string(),
    ];
    if !findings.is_empty() {
        lines.push(String::new());
        lines.push("Top candidates:".to_string());
        for finding in findings.iter().take(5) {
            lines.push(format!(
                "  - {}:{} ({}) - {}",
                finding.file_path,
                finding.start_line,
                finding.severity.as_str(),
                finding.title
            ));
        }
    }
    lines.join("\n")
}
