use super::*;

pub(in crate::capabilities::taint_iris_next) fn build_taint_iris_next_agent_prompt(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> String {
    let mut lines = vec![
        "Taint IRIS Next".to_string(),
        "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities".to_string(),
        String::new(),
        "You are Kuzushi's Taint IRIS Next agent. This is an agent-forward adaptation inspired by the IRIS paper, not the original implementation.".to_string(),
        String::new(),
        "## Objective".to_string(),
        "Use the deterministic context, threat model, CWE catalog, candidates, typed specs, and evidence bundles below to select relevant CWE themes and report only defensible findings.".to_string(),
        format!("minimum finding evidence level: {}", plan.caps.min_evidence_level),
        String::new(),
        "## Backend".to_string(),
        format!("requested: {}", plan.backend.requested),
        format!("selected: {}", plan.backend.selected),
        format!("structural engine: {}", evidence.structural_engine),
        format!("evidence tool: {}", evidence.tool),
        format!(
            "CodeQL corroboration: {}",
            if plan.backend.corroborate_with_codeql.unwrap_or(false) {
                "enabled"
            } else {
                "disabled"
            }
        ),
        plan.backend
            .codeql_db_path
            .as_ref()
            .map(|path| format!("existing CodeQL DB: {path}"))
            .unwrap_or_else(|| "existing CodeQL DB: none".to_string()),
        String::new(),
        "## Context Summary".to_string(),
        format!("languages: {}", plan.languages.join(", ")),
        format!("context artifact: {}", plan.context_status.reason),
        String::new(),
        "## Threat Model Summary".to_string(),
        format!("threat model artifact: {}", plan.threat_model_status.reason),
        String::new(),
        plan.prompt_catalog.clone(),
        String::new(),
        "## Candidate And Spec Counts".to_string(),
        format!("candidateCounts: {}", json!(evidence.candidate_counts)),
        format!("labeledSpecCounts: {}", json!(evidence.labeled_spec_counts)),
        String::new(),
        "## Evidence Bundles".to_string(),
    ];
    for item in evidence.evidence.iter().take(40) {
        lines.push(format!(
            "- {} {} {}:{} [{}] {}",
            item.cwe, item.role, item.file_path, item.line, item.evidence_level, item.snippet
        ));
    }
    lines.push(String::new());
    lines.push("## Linked Stories".to_string());
    for story in evidence.linked_stories.iter().take(20) {
        lines.push(format!(
            "- {} {}:{} -> {} ({})",
            story.cwe, story.file_path, story.source_line, story.sink_line, story.rationale
        ));
    }
    append_sanitizer_bodies_section(&mut lines, plan, evidence);
    lines.push(String::new());
    append_false_positive_patterns(&mut lines);
    lines.push(String::new());
    lines.push("## Contract".to_string());
    lines.push(
        "- Return strict JSON matching { selectedCwes, findings, triage, notes }.".to_string(),
    );
    lines.push(format!(
        "- Return at most {} findings.",
        plan.caps.max_agent_findings
    ));
    lines.push("- Cite catalogSignals for every selected CWE and every finding.".to_string());
    lines.join("\n")
}

fn append_false_positive_patterns(lines: &mut Vec<String>) {
    lines.push("## False-Positive Patterns".to_string());
    lines.push(crate::prompts::FALSE_POSITIVE_TAXONOMY.to_string());
}

fn append_sanitizer_bodies_section(
    lines: &mut Vec<String>,
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) {
    let bodies = sanitizer_body_candidates(plan, evidence);
    if bodies.is_empty() {
        return;
    }

    lines.push(String::new());
    lines.push("## Sanitizer Function Bodies".to_string());
    lines.push(
        "Audit these sanitizer-shaped functions for bypasses before rejecting linked flows."
            .to_string(),
    );
    let wrapped: Vec<(String, String)> = bodies
        .into_iter()
        .map(|body| {
            (
                format!("{} at {}:{}", body.name, body.file_path, body.start_line),
                body.source,
            )
        })
        .collect();
    lines.push(crate::prompts::render_untrusted_many(&wrapped));
}

fn sanitizer_body_candidates(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> Vec<SanitizerFunctionBody> {
    let mut files_to_scan = BTreeSet::new();
    for story in &evidence.linked_stories {
        files_to_scan.insert(story.file_path.clone());
    }
    for row in &evidence.evidence {
        files_to_scan.insert(row.file_path.clone());
    }

    let mut bodies = Vec::new();
    for relative_path in files_to_scan.iter().take(20) {
        let source_path = plan.scan_root.join(relative_path);
        let Ok(content) = fs::read_to_string(&source_path) else {
            continue;
        };
        for (name, start_line, source) in extract_sanitizer_function_bodies(&content) {
            bodies.push(SanitizerFunctionBody {
                file_path: relative_path.clone(),
                name,
                start_line,
                source,
            });
            if bodies.len() >= 8 {
                return bodies;
            }
        }
    }
    bodies
}

struct SanitizerFunctionBody {
    file_path: String,
    name: String,
    start_line: u32,
    source: String,
}

fn extract_sanitizer_function_bodies(content: &str) -> Vec<(String, u32, String)> {
    let lines = content.lines().collect::<Vec<_>>();
    let mut bodies = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let Some(name) = function_name_from_def_line(lines[index].trim_start()) else {
            index += 1;
            continue;
        };
        if !is_sanitizer_shaped_name(&name) {
            index += 1;
            continue;
        }
        let Some((start, end)) = function_body_span(&lines, index) else {
            index += 1;
            continue;
        };

        let capped_end = end.min(index + 60);
        bodies.push((
            name,
            (index + 1) as u32,
            lines[index..=capped_end].join("\n"),
        ));
        if bodies.len() >= 8 {
            return bodies;
        }
        index = start.max(end) + 1;
    }

    bodies
}

fn function_body_span(lines: &[&str], definition_line: usize) -> Option<(usize, usize)> {
    let mut brace_start = None;
    for index in definition_line..lines.len().min(definition_line + 8) {
        if lines[index].contains('{') {
            brace_start = Some(index);
            break;
        }
        if lines[index].trim_end().ends_with(';') {
            return None;
        }
    }

    let start = brace_start?;
    let mut depth = 0i32;
    let mut started = false;
    for (index, line) in lines.iter().enumerate().skip(start) {
        for byte in line.bytes() {
            match byte {
                b'{' => {
                    depth += 1;
                    started = true;
                }
                b'}' => depth -= 1,
                _ => {}
            }
        }
        if started && depth <= 0 {
            return Some((start, index));
        }
    }
    Some((start, lines.len().saturating_sub(1)))
}

fn function_name_from_def_line(line: &str) -> Option<String> {
    let paren = line.find('(')?;
    if paren == 0 {
        return None;
    }

    let before_paren = line[..paren].trim_end();
    let name_start = before_paren
        .bytes()
        .rposition(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
        .map_or(0, |position| position + 1);
    let name = &before_paren[name_start..];
    if name.is_empty() || is_control_or_logging_name(name) {
        return None;
    }
    Some(name.to_string())
}

fn is_control_or_logging_name(name: &str) -> bool {
    matches!(
        name,
        "if" | "while"
            | "for"
            | "switch"
            | "return"
            | "sizeof"
            | "elog"
            | "ereport"
            | "Assert"
            | "DEBUG"
            | "ERROR"
            | "FATAL"
            | "WARNING"
            | "NOTICE"
    )
}

fn is_sanitizer_shaped_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("check_")
        || lower.starts_with("validate_")
        || lower.starts_with("verify_")
        || lower.starts_with("safe_")
        || lower.starts_with("sanitize_")
        || lower.starts_with("escape_")
        || lower.starts_with("quote_")
        || lower.starts_with("canonicalize_")
        || matches!(
            lower.as_str(),
            "is_safe" | "is_valid" | "is_safe_path" | "is_authorized"
        )
        || lower.contains("_safe_")
        || lower.contains("_safer_")
        || lower.contains("get_safe")
        || lower.contains("ensure_")
}

#[cfg(test)]
mod sanitizer_body_tests {
    use super::*;

    #[test]
    fn extracts_sanitizer_body_from_orafce_style_source() {
        let source = r#"
static char *
get_safe_path(text *location, text *filename)
{
    char *fullname;
    bool check_locality;
    if (safe_named_location(location))
    {
        fullname = build(location, filename);
        check_locality = false;
    }
    else
    {
        fullname = build(location, filename);
        check_locality = true;
    }
    canonicalize_path(fullname);
    if (check_locality)
        check_secure_locality(fullname);
    return fullname;
}

static void
utl_file_fopen(int x)
{
    return;
}
"#;

        let bodies = extract_sanitizer_function_bodies(source);
        let (_, _, body) = bodies
            .iter()
            .find(|(name, _, _)| name == "get_safe_path")
            .expect("get_safe_path should be extracted");

        assert!(body.contains("check_locality = false"), "{body}");
        assert!(body.contains("canonicalize_path"), "{body}");
        assert!(!bodies.iter().any(|(name, _, _)| name == "utl_file_fopen"));
    }

    #[test]
    fn name_classification_only_flags_sanitizer_shapes() {
        assert!(is_sanitizer_shaped_name("check_locality"));
        assert!(is_sanitizer_shaped_name("get_safe_path"));
        assert!(is_sanitizer_shaped_name("safe_named_location"));
        assert!(is_sanitizer_shaped_name("validate_filename"));
        assert!(is_sanitizer_shaped_name("escape_string"));
        assert!(is_sanitizer_shaped_name("quote_identifier"));
        assert!(is_sanitizer_shaped_name("canonicalize_path"));
        assert!(is_sanitizer_shaped_name("ensure_directory_exists"));

        assert!(!is_sanitizer_shaped_name("utl_file_fopen"));
        assert!(!is_sanitizer_shaped_name("strcpy"));
        assert!(!is_sanitizer_shaped_name("appendStringInfo"));
        assert!(!is_sanitizer_shaped_name("PG_GETARG_TEXT_PP"));
    }
}
