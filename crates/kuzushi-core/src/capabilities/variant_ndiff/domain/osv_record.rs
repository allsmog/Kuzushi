use super::*;

/// Map an OSV API response to a `CveRecord`. OSV uses the
/// `https://api.osv.dev/v1/vulns/<id>` endpoint and returns a
/// well-defined schema documented at
/// `https://ossf.github.io/osv-schema/`.
///
/// OSV mirrors GHSA/PyPI/Go/Cargo/RubyGems advisories and adds direct
/// links to fix commits in the `references` field (with
/// `type: "FIX"`). It also exposes CWE-style classification in
/// `database_specific.cwe_ids` for GHSA-sourced advisories and uses
/// the upstream's classification for the rest. We accept whichever
/// shape comes back; missing fields are left blank rather than
/// invented.
pub(crate) fn map_osv_record(id: &str, raw: Value) -> CveRecord {
    let cwes = raw
        .pointer("/database_specific/cwe_ids")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let patches = osv_patches(&raw);
    let severity = osv_severity(&raw);
    let cvss_score = osv_cvss_score(&raw);

    CveRecord {
        id: raw
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(id)
            .to_string(),
        description: osv_description(&raw),
        cwes,
        severity,
        cvss_score,
        affected: Vec::new(),
        patches,
        published_at: raw
            .get("published")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        source: "osv".to_string(),
        raw,
    }
}

fn osv_description(raw: &Value) -> String {
    raw.get("details")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| raw.get("summary").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string()
}

fn osv_patches(raw: &Value) -> Vec<CvePatchRef> {
    let Some(refs) = raw.get("references").and_then(Value::as_array) else {
        return Vec::new();
    };
    refs.iter()
        .filter_map(|reference| {
            let url = reference.get("url").and_then(Value::as_str)?;
            let kind = reference
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("WEB");
            if !is_osv_patch_kind(kind, url) {
                return None;
            }
            Some(CvePatchRef {
                url: url.to_string(),
                kind: "osv".to_string(),
                title: None,
            })
        })
        .collect()
}

fn is_osv_patch_kind(kind: &str, url: &str) -> bool {
    let upper = kind.to_ascii_uppercase();
    if upper == "FIX" {
        return true;
    }
    url.contains("/commit/")
        || url.contains("/pull/")
        || url.ends_with(".diff")
        || url.ends_with(".patch")
}

fn osv_severity(raw: &Value) -> Option<String> {
    // Prefer the OSV `database_specific.severity` text label (HIGH /
    // CRITICAL etc., GHSA-sourced) before parsing CVSS vectors. Either
    // path returns None if the upstream didn't classify the entry.
    if let Some(label) = raw
        .pointer("/database_specific/severity")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return Some(label.to_ascii_uppercase());
    }
    osv_cvss_score(raw).map(severity_from_cvss)
}

fn osv_cvss_score(raw: &Value) -> Option<f64> {
    let Some(items) = raw.get("severity").and_then(Value::as_array) else {
        return None;
    };
    for item in items {
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
        if !kind.starts_with("CVSS_V") {
            continue;
        }
        let score = item.get("score").and_then(Value::as_str)?;
        if let Some(base) = parse_cvss_base_score(score) {
            return Some(base);
        }
    }
    None
}

fn parse_cvss_base_score(vector: &str) -> Option<f64> {
    // OSV stores CVSS as a vector string like "CVSS:3.1/AV:N/.../I:H/A:H"
    // — there's no scalar in the schema. Computing the base score from
    // the vector is a non-trivial NIST calculation; we conservatively
    // return None here and let `osv_severity` fall back to the text
    // label. If the vector happens to be a bare numeric string (some
    // forks store it that way), parse it.
    vector.trim().parse::<f64>().ok()
}

fn severity_from_cvss(score: f64) -> String {
    if score >= 9.0 {
        "CRITICAL".to_string()
    } else if score >= 7.0 {
        "HIGH".to_string()
    } else if score >= 4.0 {
        "MEDIUM".to_string()
    } else {
        "LOW".to_string()
    }
}
