use super::*;

pub(crate) fn map_nvd_record(id: &str, raw: Value) -> Option<CveRecord> {
    let first = first_nvd_vulnerability(&raw)?;
    let cve = nvd_cve_payload(&first);
    Some(CveRecord {
        id: id.to_ascii_uppercase(),
        description: nvd_english_description(&cve),
        cwes: nvd_cwes(&cve),
        severity: nvd_severity(&cve),
        cvss_score: nvd_cvss_score(&cve),
        affected: Vec::new(),
        patches: nvd_patches(&cve),
        published_at: cve
            .get("published")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        source: "nvd".to_string(),
        raw: first,
    })
}

pub(crate) fn first_nvd_vulnerability(raw: &Value) -> Option<Value> {
    raw.get("vulnerabilities")?.as_array()?.first().cloned()
}

pub(crate) fn nvd_cve_payload(vulnerability: &Value) -> Value {
    vulnerability
        .get("cve")
        .cloned()
        .unwrap_or_else(|| json!({}))
}

pub(crate) fn nvd_english_description(cve: &Value) -> String {
    cve.get("descriptions")
        .and_then(Value::as_array)
        .and_then(|items| items.iter().find_map(nvd_english_description_value))
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn nvd_english_description_value(item: &Value) -> Option<&str> {
    if item.get("lang").and_then(Value::as_str) != Some("en") {
        return None;
    }
    item.get("value").and_then(Value::as_str)
}

pub(crate) fn nvd_cwes(cve: &Value) -> Vec<String> {
    cve.get("weaknesses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(nvd_weakness_descriptions)
        .filter_map(|description| description.get("value").and_then(Value::as_str))
        .filter(|value| value.starts_with("CWE-"))
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn nvd_weakness_descriptions(weakness: &Value) -> &[Value] {
    weakness
        .get("description")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

pub(crate) fn nvd_patches(cve: &Value) -> Vec<CvePatchRef> {
    cve.get("references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(nvd_patch_ref)
        .collect()
}

pub(crate) fn nvd_patch_ref(reference: &Value) -> Option<CvePatchRef> {
    let url = reference.get("url").and_then(Value::as_str)?;
    let tags = nvd_reference_tags(reference);
    if !is_nvd_patch_reference(url, &tags) {
        return None;
    }
    Some(CvePatchRef {
        url: url.to_string(),
        kind: "nvd".to_string(),
        title: (!tags.is_empty()).then(|| tags.join(",")),
    })
}

pub(crate) fn nvd_reference_tags(reference: &Value) -> Vec<String> {
    reference
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn is_nvd_patch_reference(url: &str, tags: &[String]) -> bool {
    tags.iter().any(|tag| tag == "Patch")
        || url.contains("/commit/")
        || url.contains("/pull/")
        || url.ends_with(".diff")
        || url.ends_with(".patch")
}

pub(crate) fn nvd_severity(cve: &Value) -> Option<String> {
    cve.pointer("/metrics/cvssMetricV31/0/baseSeverity")
        .or_else(|| cve.pointer("/metrics/cvssMetricV31/0/cvssData/baseSeverity"))
        .and_then(Value::as_str)
        .map(str::to_ascii_uppercase)
}
