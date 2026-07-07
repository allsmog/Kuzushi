use super::*;

pub(crate) fn normalize_variant_findings(
    raw: Value,
    target: &Path,
    repo_name: &str,
    original: &Finding,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let variants = variants_array(raw);
    let mut deduped: BTreeMap<String, Finding> = BTreeMap::new();
    for item in variants.into_iter() {
        let Some(finding) = variant_finding_from_item(item, target, repo_name, original)? else {
            continue;
        };
        deduped
            .entry(finding.fingerprint.clone())
            .or_insert(finding);
        if deduped.len() >= max_findings {
            break;
        }
    }
    let mut findings = deduped.into_values().collect::<Vec<_>>();
    findings.sort_by_key(|finding| finding.severity);
    findings.reverse();
    Ok(findings)
}

fn variant_finding_from_item(
    item: Value,
    target: &Path,
    repo_name: &str,
    original: &Finding,
) -> Result<Option<Finding>> {
    let Some(object) = item.as_object() else {
        return Ok(None);
    };
    let Some(raw_file_path) = read_object_string(object, &["filePath", "file_path"]) else {
        return Ok(None);
    };
    let file_path = normalize_file_path(target, &raw_file_path);
    let start_line = read_object_u64(object, &["startLine", "start_line"])
        .filter(|line| *line > 0)
        .unwrap_or(1) as u32;
    if file_path == original.file_path && start_line == original.start_line {
        return Ok(None);
    }
    let confidence = required_variant_string(object, "confidence", original, &file_path)?;
    if confidence.eq_ignore_ascii_case("LOW") {
        return Ok(None);
    }
    let severity = severity_from_agent(&required_variant_string(
        object, "severity", original, &file_path,
    )?);
    Ok(Some(build_variant_finding(
        object, repo_name, original, file_path, start_line, confidence, severity,
    )))
}

fn required_variant_string(
    object: &Map<String, Value>,
    key: &str,
    original: &Finding,
    file_path: &str,
) -> Result<String> {
    read_object_string(object, &[key]).with_context(|| {
        format!(
            "variant finding for {} in {file_path} missing required `{key}`",
            original.rule_id
        )
    })
}

fn build_variant_finding(
    object: &Map<String, Value>,
    repo_name: &str,
    original: &Finding,
    file_path: String,
    start_line: u32,
    confidence: String,
    severity: Severity,
) -> Finding {
    let cwes = read_object_string_array(object, &["cwe", "cwes"]);
    let message = variant_message(
        read_object_string(object, &["message"]).as_deref(),
        read_object_string(object, &["rationale"]).as_deref(),
        &confidence,
        &cwes,
        &format!("Variant of {}", original.rule_id),
    );
    let mut finding = Finding::new_tool(
        "variant-analysis",
        format!("variant/{}", original.rule_id),
        file_path.clone(),
        start_line,
        None,
        severity,
        message,
    );
    finding.fingerprint = stable_fingerprint(&[
        repo_name,
        "variant-analysis",
        &original.rule_id,
        &file_path,
        &start_line.to_string(),
    ]);
    finding
}
