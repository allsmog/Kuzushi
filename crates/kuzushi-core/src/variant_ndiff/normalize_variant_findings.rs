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
        let Value::Object(object) = item else {
            continue;
        };
        let Some(raw_file_path) = read_object_string(&object, &["filePath", "file_path"]) else {
            continue;
        };
        let file_path = normalize_file_path(target, &raw_file_path);
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .filter(|line| *line > 0)
            .unwrap_or(1) as u32;
        if file_path == original.file_path && start_line == original.start_line {
            continue;
        }
        let confidence =
            read_object_string(&object, &["confidence"]).unwrap_or_else(|| "MEDIUM".to_string());
        if confidence.eq_ignore_ascii_case("LOW") {
            continue;
        }
        let severity = severity_from_agent(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or(original.severity.as_str()),
        );
        let rule_id = format!("variant/{}", original.rule_id);
        let cwes = read_object_string_array(&object, &["cwe", "cwes"]);
        let message = variant_message(
            read_object_string(&object, &["message"]).as_deref(),
            read_object_string(&object, &["rationale"]).as_deref(),
            &confidence,
            &cwes,
            &format!("Variant of {}", original.rule_id),
        );
        let mut finding = Finding::new_tool(
            "variant-analysis",
            rule_id,
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
