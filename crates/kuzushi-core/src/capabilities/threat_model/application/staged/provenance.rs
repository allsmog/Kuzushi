use serde_json::{json, Map, Value};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Stamp deterministic build provenance onto the document: the target's git
/// revision (the refine-mode anchor), a build timestamp, and which pipeline
/// produced the model. Merges into any model-emitted provenance object so
/// source-confidence notes from the LLM survive.
pub(crate) fn stamp_provenance(document: &mut Value, target: &Path, pipeline: &str) {
    let Some(provenance) = provenance_object(document) else {
        return;
    };
    provenance.insert("pipeline".to_string(), json!(pipeline));
    provenance.insert("builtAtMs".to_string(), json!(epoch_ms()));
    if let Some(metadata) = crate::workspace::target_git_metadata(target) {
        provenance.insert("revision".to_string(), json!(metadata.sha));
        provenance.insert("revisionDirty".to_string(), json!(metadata.dirty));
    }
}

/// Stamp how this build used the previously persisted model as seed context.
/// `seeded_from` is the live model at build time (None for fresh or first
/// builds); the caller reads it before the new document overwrites it, so
/// this stays pure.
pub(crate) fn stamp_seed_lineage(
    document: &mut Value,
    seed_mode: &str,
    seeded_from: Option<&Value>,
) {
    let summary = seeded_from.map(seeded_from_summary);
    let Some(provenance) = provenance_object(document) else {
        return;
    };
    provenance.insert("seedMode".to_string(), json!(seed_mode));
    if let Some(summary) = summary {
        provenance.insert("seededFrom".to_string(), summary);
    }
}

fn seeded_from_summary(previous: &Value) -> Value {
    json!({
        "methodology": previous
            .get("methodology")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
        "sha256": crate::findings::threat_model_document_sha256(previous),
    })
}

fn provenance_object(document: &mut Value) -> Option<&mut Map<String, Value>> {
    let root = document.as_object_mut()?;
    if !root.get("provenance").is_some_and(Value::is_object) {
        root.insert("provenance".to_string(), json!({}));
    }
    root.get_mut("provenance")?.as_object_mut()
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_pipeline_and_built_at_and_merges_into_existing_provenance() {
        let temp = tempfile::tempdir().unwrap();
        let mut document = json!({
            "provenance": {"sourceLabels": ["context"]},
        });
        stamp_provenance(&mut document, temp.path(), "single");
        assert_eq!(document["provenance"]["pipeline"], json!("single"));
        assert!(document["provenance"]["builtAtMs"].as_u64().unwrap() > 0);
        assert_eq!(
            document["provenance"]["sourceLabels"],
            json!(["context"]),
            "model-emitted provenance keys must survive the stamp"
        );
        assert!(
            document["provenance"].get("revision").is_none(),
            "non-git target must not claim a revision"
        );
    }

    #[test]
    fn seed_lineage_records_mode_and_seeded_from_identity() {
        let previous = json!({"methodology": "pasta", "threats": []});
        let mut document = json!({});
        stamp_seed_lineage(&mut document, "seeded", Some(&previous));
        assert_eq!(document["provenance"]["seedMode"], json!("seeded"));
        assert_eq!(
            document["provenance"]["seededFrom"]["methodology"],
            json!("pasta")
        );
        assert!(document["provenance"]["seededFrom"]["sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[test]
    fn fresh_seed_lineage_records_mode_without_seeded_from() {
        let mut document = json!({});
        stamp_seed_lineage(&mut document, "fresh", None);
        assert_eq!(document["provenance"]["seedMode"], json!("fresh"));
        assert!(document["provenance"].get("seededFrom").is_none());
    }

    #[test]
    fn non_object_document_is_left_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let mut document = json!([]);
        stamp_provenance(&mut document, temp.path(), "single");
        assert_eq!(document, json!([]));
    }
}
