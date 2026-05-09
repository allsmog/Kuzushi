use super::*;

pub(crate) fn nvd_cvss_score(cve: &Value) -> Option<f64> {
    cve.pointer("/metrics/cvssMetricV31/0/cvssData/baseScore")
        .and_then(Value::as_f64)
}

pub(crate) fn map_ghsa_record(id: &str, raw: Value) -> CveRecord {
    let cwes = raw
        .get("cwes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("cwe_id").and_then(Value::as_str))
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let patches = raw
        .get("references")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|url| {
                    url.contains("/commit/")
                        || url.contains("/pull/")
                        || url.ends_with(".diff")
                        || url.ends_with(".patch")
                })
                .map(|url| CvePatchRef {
                    url: url.to_string(),
                    kind: "ghsa".to_string(),
                    title: None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    CveRecord {
        id: raw
            .get("cve_id")
            .and_then(Value::as_str)
            .unwrap_or(id)
            .to_string(),
        description: raw
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        cwes,
        severity: raw
            .get("severity")
            .and_then(Value::as_str)
            .map(str::to_ascii_uppercase),
        cvss_score: raw.pointer("/cvss/score").and_then(Value::as_f64),
        affected: Vec::new(),
        patches,
        published_at: raw
            .get("published_at")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        source: "ghsa".to_string(),
        raw,
    }
}

pub(crate) fn choose_primary_patch_url(record: &CveRecord) -> Option<String> {
    fn rank(url: &str) -> usize {
        if url.ends_with(".diff") {
            0
        } else if url.ends_with(".patch") {
            1
        } else if url.contains("/commit/") {
            2
        } else if url.contains("/pull/") {
            3
        } else {
            4
        }
    }
    record
        .patches
        .iter()
        .min_by_key(|patch| rank(&patch.url))
        .map(|patch| patch.url.clone())
}
