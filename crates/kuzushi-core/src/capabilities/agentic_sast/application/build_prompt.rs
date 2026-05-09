use super::*;

pub(crate) fn build_agentic_sast_prompt(
    target: &Path,
    options: &AgenticSastInput,
    inventory: &[(String, String)],
    review_context: Option<&str>,
    whitebox_static: bool,
) -> String {
    let mut prompt = vec![
        "Scan this repository for concrete application-security vulnerabilities.".to_string(),
        format!("Target: {}", target.display()),
        format!("Severity filter: {}", options.severity.join(", ")),
        format!("Max findings: {}", options.max_findings),
        format!(
            "Exclude paths/globs: {}",
            if options.exclude_patterns.is_empty() {
                "(none)".to_string()
            } else {
                options.exclude_patterns.join(", ")
            }
        ),
        String::new(),
        "Evidence requirements: name the attacker-controlled source, sink, missing guard, and exact file:line. Omit uncertain or hypothetical findings.".to_string(),
    ];
    if whitebox_static {
        prompt.push(String::new());
        prompt.push(whitebox_static_triage_prompt_block().to_string());
    }
    if let Some(review_context) = review_context {
        prompt.push(String::new());
        prompt.push(review_context.to_string());
    }
    prompt.push(String::new());
    prompt.push("Repository inventory and snippets:".to_string());
    if inventory.is_empty() {
        prompt.push("(no readable source snippets found)".to_string());
    }
    for (path, snippet) in inventory {
        prompt.push(format!("\n--- {path} ---\n{snippet}"));
    }
    prompt.join("\n")
}

pub(crate) fn summarize_agentic_findings_for_review(findings: &[Finding]) -> String {
    let mut lines = vec![
        "Second pass context: validate these first-pass findings and report only new or corrected findings.".to_string(),
    ];
    for finding in findings.iter().take(20) {
        lines.push(format!(
            "- [{}] {} at {}:{}: {}",
            finding.severity.as_str(),
            finding.rule_id,
            finding.file_path,
            finding.start_line,
            finding.title
        ));
    }
    lines.join("\n")
}
