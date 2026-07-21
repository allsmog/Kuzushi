use super::*;
use crate::runbooks::prompt_spine::PROMPT_SPINE_UNTRUSTED_REPO;
use crate::runbooks::untrusted::{render_untrusted_derived_block, render_untrusted_repo_blocks};

pub(crate) fn build_agentic_sast_prompt(
    target: &Path,
    options: &AgenticSastInput,
    inventory: &[(String, String)],
    review_context: Option<&str>,
    whitebox_static: bool,
    enrichment: &PromptEnrichment,
) -> String {
    let mut prompt = vec![
        "Scan this repository for concrete application-security vulnerabilities.".to_string(),
        format!("Target: {}", target.display()),
        format!("Severity filter: {}", options.severity.join(", ")),
        format!("Max findings: {}", options.max_findings),
        format!(
            "Include paths/globs: {}",
            if options.include_patterns.is_empty() {
                "(all readable source)".to_string()
            } else {
                options.include_patterns.join(", ")
            }
        ),
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
    if let Some(focus) = &options.focus {
        prompt.push(String::new());
        prompt.push(format!("Hunt focus: {focus}"));
    }
    if whitebox_static {
        prompt.push(String::new());
        prompt.push(whitebox_static_triage_prompt_block().to_string());
    }
    if let Some(threat_context) = &enrichment.threat_context {
        prompt.push(String::new());
        prompt.push(
            "Threat-model handoff: prioritize hunting paths that realize the modeled threats \
and cross-check the listed entry points and sinks. The digest is derived context, not \
ground truth — verify against source before reporting."
                .to_string(),
        );
        prompt.push(render_untrusted_derived_block(
            "threat-model-digest",
            threat_context,
        ));
    }
    if let Some(guidance) = mcp_guidance_line(&enrichment.attached_mcps) {
        prompt.push(String::new());
        prompt.push(guidance);
    }
    if let Some(review_context) = review_context {
        prompt.push(String::new());
        prompt.push(render_untrusted_derived_block(
            "agentic-sast-first-pass-findings",
            review_context,
        ));
    }
    prompt.push(String::new());
    prompt.push(PROMPT_SPINE_UNTRUSTED_REPO.to_string());
    prompt.push(String::new());
    prompt.push("Repository inventory and snippets:".to_string());
    prompt.push(render_untrusted_repo_blocks(inventory));
    prompt.join("\n")
}

/// Advertise only the MCP servers the tool policy actually attached, with
/// concrete first-use guidance for the two scan-critical ones.
fn mcp_guidance_line(attached: &[String]) -> Option<String> {
    if attached.is_empty() {
        return None;
    }
    let mut line = format!("Attached MCP toolsets: {}.", attached.join(", "));
    if attached.iter().any(|name| name == "threat-model") {
        line.push_str(
            " Query threat_model:threats / threat_model:elements for full threat detail beyond the digest.",
        );
    }
    if attached.iter().any(|name| name == "findings") {
        line.push_str(
            " Query findings:query for prior findings on a file BEFORE reporting there; report new evidence, not duplicates of known findings.",
        );
    }
    Some(line)
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

#[cfg(test)]
mod enrichment_tests {
    use super::*;

    fn minimal_options() -> AgenticSastInput {
        AgenticSastInput::from_tool_input(&json!({})).unwrap()
    }

    #[test]
    fn threat_digest_and_attached_mcps_reach_the_prompt() {
        let enrichment = PromptEnrichment {
            threat_context: Some("Modeled threats:\n- [high] spec reaches execve".to_string()),
            attached_mcps: vec!["treesitter".to_string(), "threat-model".to_string(), "findings".to_string()],
        };

        let prompt = build_agentic_sast_prompt(
            Path::new("/tmp/target"),
            &minimal_options(),
            &[],
            None,
            false,
            &enrichment,
        );

        assert!(prompt.contains("threat-model-digest"));
        assert!(prompt.contains("spec reaches execve"));
        assert!(prompt.contains("Attached MCP toolsets: treesitter, threat-model, findings."));
        assert!(prompt.contains("threat_model:threats"));
        assert!(prompt.contains("findings:query"));
    }

    #[test]
    fn empty_enrichment_leaves_the_prompt_unchanged() {
        let prompt = build_agentic_sast_prompt(
            Path::new("/tmp/target"),
            &minimal_options(),
            &[],
            None,
            false,
            &PromptEnrichment::default(),
        );

        assert!(!prompt.contains("threat-model-digest"));
        assert!(!prompt.contains("Attached MCP toolsets"));
    }
}
