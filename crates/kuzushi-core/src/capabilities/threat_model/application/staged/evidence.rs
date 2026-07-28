use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Anti-hallucination gate: every evidence ref a threat cites must exist in
/// the research dossier's evidence index (finding fingerprints, mined commit
/// shas and their 12-char prefixes, surface/finding `path:line` anchors).
/// Unindexed refs are dropped with a warning instead of shipping invented
/// provenance.
pub(crate) fn retain_indexed_evidence(
    document: &mut Value,
    index: &BTreeSet<String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(threats) = document.get_mut("threats").and_then(Value::as_array_mut) else {
        return warnings;
    };
    for threat in threats {
        retain_threat_evidence(threat, index, &mut warnings);
    }
    warnings
}

fn retain_threat_evidence(threat: &mut Value, index: &BTreeSet<String>, warnings: &mut Vec<String>) {
    let threat_label = threat_label(threat);
    let Some(evidence) = threat.get_mut("evidence").and_then(Value::as_array_mut) else {
        return;
    };
    evidence.retain(|entry| {
        let keep = evidence_entry_is_indexed(entry, index);
        if !keep {
            warnings.push(format!(
                "{threat_label}: dropped unindexed evidence ref {}",
                evidence_entry_ref(entry).unwrap_or_else(|| entry.to_string())
            ));
        }
        keep
    });
}

fn threat_label(threat: &Value) -> String {
    threat
        .get("stableId")
        .or_else(|| threat.get("id"))
        .or_else(|| threat.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("threat")
        .to_string()
}

fn evidence_entry_is_indexed(entry: &Value, index: &BTreeSet<String>) -> bool {
    evidence_entry_ref(entry).is_some_and(|reference| index.contains(&reference))
}

fn evidence_entry_ref(entry: &Value) -> Option<String> {
    match entry {
        Value::String(reference) => Some(reference.trim().to_string()),
        Value::Object(fields) => fields
            .get("ref")
            .and_then(Value::as_str)
            .map(|reference| reference.trim().to_string()),
        _ => None,
    }
}

/// Deterministic, content-addressed threat identity that survives rebuilds:
/// `tm-<12 hex of sha256(category|surface|asset)>`. Model-emitted ids stay in
/// `id`; downstream diffing keys on `stableId`.
pub(crate) fn assign_stable_ids(document: &mut Value) {
    let Some(threats) = document.get_mut("threats").and_then(Value::as_array_mut) else {
        return;
    };
    for threat in threats {
        let key = stable_id_key(threat);
        threat["stableId"] = json!(stable_threat_id(&key));
    }
}

fn stable_id_key(threat: &Value) -> String {
    let field = |keys: &[&str], fallback: &str| -> String {
        keys.iter()
            .find_map(|key| threat.get(*key).and_then(Value::as_str))
            .unwrap_or(fallback)
            .to_string()
    };
    let surface = threat
        .get("surface")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| first_affected_file(threat))
        .unwrap_or_else(|| field(&["title"], "unknown-surface"));
    format!(
        "{}|{}|{}",
        field(&["category"], "uncategorized"),
        surface,
        field(&["asset"], "unknown-asset"),
    )
}

fn first_affected_file(threat: &Value) -> Option<String> {
    let files = threat.get("affectedFiles")?.as_array()?;
    files.iter().find_map(|file| match file {
        Value::String(path) => Some(path.clone()),
        Value::Object(fields) => fields
            .get("filePath")
            .and_then(Value::as_str)
            .map(str::to_string),
        _ => None,
    })
}

pub(crate) fn stable_threat_id(key: &str) -> String {
    // prompt_content_sha256 returns a "sha256:<hex>" token; the id wants
    // twelve hex chars, not the scheme prefix.
    let digest = crate::options::prompt_content_sha256(key);
    let hex = digest.strip_prefix("sha256:").unwrap_or(&digest);
    format!("tm-{}", &hex[..hex.len().min(12)])
}

/// "Evidence raises likelihood; it is not the threat": ≥3 corroborated
/// evidence rows bump one band, ≥3 variant siblings bump one more, capped at
/// almost_certain on the five-band ladder. Legacy three-band values are
/// canonicalized first (low->rare, medium->possible, high->likely).
/// Vocabulary outside the closed band set passes through unchanged — no
/// fabricated confidence.
pub(crate) fn adjusted_likelihood(base: &str, evidence_rows: usize, sibling_count: usize) -> String {
    const BANDS: [&str; 5] = ["very_rare", "rare", "possible", "likely", "almost_certain"];
    let Some(canonical) = crate::capabilities::threat_model::normalize_likelihood(base) else {
        return base.to_string();
    };
    let position = BANDS
        .iter()
        .position(|band| *band == canonical)
        .expect("normalize_likelihood only returns ladder bands");
    let bumps = usize::from(evidence_rows >= 3) + usize::from(sibling_count >= 3);
    BANDS[(position + bumps).min(BANDS.len() - 1)].to_string()
}

/// Persisted display ids (`T1..Tn`) keyed by `stableId`: assigned once on
/// first appearance in document order, then carried forward verbatim across
/// refines — never renumbered, so cross-session references stay valid.
pub(crate) fn assign_display_ids(document: &mut Value, previous: Option<&Value>) {
    let mut by_stable_id = std::collections::BTreeMap::new();
    let mut next_index = 1usize;
    for source in [previous, Some(&*document)].into_iter().flatten() {
        collect_display_ids(source, &mut by_stable_id, &mut next_index);
    }
    let Some(threats) = document.get_mut("threats").and_then(Value::as_array_mut) else {
        return;
    };
    for threat in threats {
        let Some(stable_id) = threat.get("stableId").and_then(Value::as_str) else {
            continue;
        };
        let display_id = by_stable_id
            .entry(stable_id.to_string())
            .or_insert_with(|| {
                let assigned = format!("T{next_index}");
                next_index += 1;
                assigned
            })
            .clone();
        threat["displayId"] = json!(display_id);
    }
}

fn collect_display_ids(
    document: &Value,
    by_stable_id: &mut std::collections::BTreeMap<String, String>,
    next_index: &mut usize,
) {
    let Some(threats) = document.get("threats").and_then(Value::as_array) else {
        return;
    };
    for threat in threats {
        let (Some(stable_id), Some(display_id)) = (
            threat.get("stableId").and_then(Value::as_str),
            threat.get("displayId").and_then(Value::as_str),
        ) else {
            continue;
        };
        by_stable_id
            .entry(stable_id.to_string())
            .or_insert_with(|| display_id.to_string());
        if let Some(index) = display_id.strip_prefix('T').and_then(|n| n.parse::<usize>().ok()) {
            *next_index = (*next_index).max(index + 1);
        }
    }
}

/// Apply the likelihood rule over every threat using its normalized
/// evidence rows. Sibling counts arrive with the variant scan (Phase 4) and
/// default to zero here.
pub(crate) fn apply_evidence_likelihood(document: &mut Value) {
    let Some(threats) = document.get_mut("threats").and_then(Value::as_array_mut) else {
        return;
    };
    for threat in threats {
        let evidence_rows = threat
            .get("evidence")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let Some(base) = threat.get("likelihood").and_then(Value::as_str) else {
            continue;
        };
        threat["likelihood"] = json!(adjusted_likelihood(base, evidence_rows, 0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unindexed_evidence_refs_are_dropped_with_warnings() {
        let mut document = json!({
            "threats": [{
                "id": "T-1",
                "title": "RCE via upload",
                "evidence": [
                    {"kind": "finding", "ref": "fp3_real", "summary": "confirmed"},
                    {"kind": "commit", "ref": "deadbeef9999", "summary": "invented"},
                    "fp3_also_real"
                ]
            }]
        });
        let index: BTreeSet<String> =
            ["fp3_real".to_string(), "fp3_also_real".to_string()].into();
        let warnings = retain_indexed_evidence(&mut document, &index);
        let evidence = document["threats"][0]["evidence"].as_array().unwrap();
        assert_eq!(evidence.len(), 2);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("deadbeef9999"));
    }

    #[test]
    fn stable_ids_are_deterministic_and_content_addressed() {
        let mut document = json!({
            "threats": [
                {"category": "tampering", "surface": "POST /upload", "asset": "blob store"},
                {"category": "tampering", "surface": "POST /upload", "asset": "blob store"}
            ]
        });
        assign_stable_ids(&mut document);
        let first = document["threats"][0]["stableId"].as_str().unwrap().to_string();
        let second = document["threats"][1]["stableId"].as_str().unwrap().to_string();
        assert!(first.starts_with("tm-") && first.len() == 15);
        assert!(
            first[3..].chars().all(|c| c.is_ascii_hexdigit()),
            "stableId must be tm-<12 hex>, got {first}"
        );
        assert_eq!(first, second, "same cluster key must yield the same stableId");
    }

    #[test]
    fn likelihood_bumps_one_band_at_three_evidence_rows_and_caps_at_almost_certain() {
        assert_eq!(adjusted_likelihood("very_rare", 2, 0), "very_rare");
        assert_eq!(adjusted_likelihood("rare", 3, 0), "possible");
        assert_eq!(adjusted_likelihood("possible", 3, 3), "almost_certain");
        assert_eq!(adjusted_likelihood("likely", 9, 9), "almost_certain");
        assert_eq!(adjusted_likelihood("almost_certain", 9, 9), "almost_certain");
    }

    #[test]
    fn legacy_three_band_likelihood_canonicalizes_onto_the_ladder() {
        assert_eq!(adjusted_likelihood("low", 0, 0), "rare");
        assert_eq!(adjusted_likelihood("medium", 0, 0), "possible");
        assert_eq!(adjusted_likelihood("high", 0, 0), "likely");
        assert_eq!(adjusted_likelihood("out-of-vocabulary", 9, 9), "out-of-vocabulary");
    }

    #[test]
    fn display_ids_assign_in_document_order_and_survive_refines() {
        let mut first = json!({
            "threats": [
                {"stableId": "tm-aaaaaaaaaaaa", "title": "A"},
                {"stableId": "tm-bbbbbbbbbbbb", "title": "B"}
            ]
        });
        assign_display_ids(&mut first, None);
        assert_eq!(first["threats"][0]["displayId"], "T1");
        assert_eq!(first["threats"][1]["displayId"], "T2");

        // Refine drops A, keeps B, adds C: B keeps T2, C continues at T3 —
        // T1 is never reused.
        let mut refined = json!({
            "threats": [
                {"stableId": "tm-cccccccccccc", "title": "C"},
                {"stableId": "tm-bbbbbbbbbbbb", "title": "B"}
            ]
        });
        assign_display_ids(&mut refined, Some(&first));
        assert_eq!(refined["threats"][0]["displayId"], "T3");
        assert_eq!(refined["threats"][1]["displayId"], "T2");
    }
}
