use super::*;

pub(crate) fn normalize_ndiff_findings(
    raw: Value,
    repo_name: &str,
    advisory_id: &str,
    pattern: &Map<String, Value>,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let variants = variants_array(raw);
    let mut findings = Vec::new();
    for item in variants.into_iter() {
        let Some(finding) = ndiff_finding_from_item(item, repo_name, advisory_id, pattern)? else {
            continue;
        };
        findings.push(finding);
        if findings.len() >= max_findings {
            break;
        }
    }
    Ok(findings)
}

fn ndiff_finding_from_item(
    item: Value,
    repo_name: &str,
    advisory_id: &str,
    pattern: &Map<String, Value>,
) -> Result<Option<Finding>> {
    let Some(object) = item.as_object() else {
        return Ok(None);
    };
    let Some(file_path) = read_object_string(object, &["filePath", "file_path"]) else {
        return Ok(None);
    };
    let start_line = read_object_u64(object, &["startLine", "start_line"])
        .filter(|line| *line > 0)
        .unwrap_or(1) as u32;
    let confidence = required_ndiff_string(object, "confidence", advisory_id, &file_path)?;
    if confidence.eq_ignore_ascii_case("LOW") {
        return Ok(None);
    }
    let severity = severity_from_agent(&required_ndiff_string(
        object,
        "severity",
        advisory_id,
        &file_path,
    )?);
    Ok(Some(build_ndiff_finding(
        object,
        repo_name,
        advisory_id,
        pattern,
        file_path,
        start_line,
        confidence,
        severity,
    )))
}

fn required_ndiff_string(
    object: &Map<String, Value>,
    key: &str,
    advisory_id: &str,
    file_path: &str,
) -> Result<String> {
    read_object_string(object, &[key]).with_context(|| {
        format!("n-day variant finding for {advisory_id} in {file_path} missing required `{key}`")
    })
}

fn build_ndiff_finding(
    object: &Map<String, Value>,
    repo_name: &str,
    advisory_id: &str,
    pattern: &Map<String, Value>,
    file_path: String,
    start_line: u32,
    confidence: String,
    severity: Severity,
) -> Finding {
    let cwes = ndiff_cwes(object, pattern);
    let message = variant_message(
        read_object_string(object, &["message"]).as_deref(),
        read_object_string(object, &["rationale"]).as_deref(),
        &confidence,
        &cwes,
        &ndiff_fallback_message(advisory_id, pattern),
    );
    let mut finding = Finding::new_tool(
        "n-day-diff-hunter",
        format!("n-day/{advisory_id}"),
        file_path.clone(),
        start_line,
        None,
        severity,
        message,
    );
    finding.fingerprint = format!("{repo_name}:ndiff/{advisory_id}/{file_path}:{start_line}");
    finding
}

fn ndiff_cwes(object: &Map<String, Value>, pattern: &Map<String, Value>) -> Vec<String> {
    let from_result = read_object_string_array(object, &["cwe", "cwes"]);
    if from_result.is_empty() {
        read_object_string_array(pattern, &["cwe", "cwes"])
    } else {
        from_result
    }
}

fn ndiff_fallback_message(advisory_id: &str, pattern: &Map<String, Value>) -> String {
    format!(
        "Possible unpatched variant of {}: {}",
        advisory_id,
        read_object_string(pattern, &["vulnerableShape", "vulnerable_shape"]).unwrap_or_default()
    )
}

pub(crate) fn derive_whitebox_variant_pattern(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
) -> Option<WhiteboxVariantPattern> {
    let corpus = variant_pattern_corpus(finding, evidence_nodes);
    let source_tokens = matching_tokens(&corpus, WHITEBOX_SOURCE_TOKENS);
    let sink_tokens = matching_tokens(&corpus, WHITEBOX_SINK_TOKENS);
    if source_tokens.is_empty() || sink_tokens.is_empty() {
        return None;
    }

    let mut keywords = BTreeSet::new();
    keywords.extend(source_tokens.iter().cloned());
    keywords.extend(sink_tokens.iter().cloned());
    for token in finding
        .rule_id
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::trim)
        .filter(|token| token.len() >= 4)
        .take(4)
    {
        keywords.insert(token.to_ascii_lowercase());
    }

    Some(WhiteboxVariantPattern {
        original_fingerprint: finding.fingerprint.clone(),
        rule_id: finding.rule_id.clone(),
        file_path: finding.file_path.clone(),
        start_line: finding.start_line,
        source_tokens: source_tokens.clone(),
        sink_tokens: sink_tokens.clone(),
        missing_guard_tokens: WHITEBOX_GUARD_TOKENS
            .iter()
            .map(|token| (*token).to_string())
            .collect(),
        keywords: keywords.into_iter().collect(),
        description: format!(
            "Find sibling code where {} reaches {} without an obvious sanitizer or guard.",
            source_tokens.join(" or "),
            sink_tokens.join(" or ")
        ),
    })
}
