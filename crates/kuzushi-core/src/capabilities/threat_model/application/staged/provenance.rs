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
/// `seed_mode` is the OBSERVED mode — what actually reached the prompt.
/// `seed_mode_requested` is stamped only when the request differed, so a run
/// whose request could not be honored (a first build asking to seed, an
/// explicit sources list excluding the model) stays auditable in both terms.
pub(crate) fn stamp_seed_lineage(
    document: &mut Value,
    seed_mode: &str,
    seed_mode_requested: Option<&str>,
    seeded_from: Option<&Value>,
) {
    let summary = seeded_from.map(seeded_from_summary);
    let Some(provenance) = provenance_object(document) else {
        return;
    };
    provenance.insert("seedMode".to_string(), json!(seed_mode));
    if let Some(requested) = seed_mode_requested {
        provenance.insert("seedModeRequested".to_string(), json!(requested));
    }
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

/// Overwrite `provenance.sources` with the loader's system-attested record of
/// what the build consumed.
///
/// The model is asked to describe its own inputs and cannot be trusted to: an
/// observed build echoed the untrusted-content fence delimiter
/// (`UNTRUSTED_REPO_BEGIN`) into this field. When `record_model_claim` is set
/// and the model claimed something different, the claim is preserved verbatim
/// under `modelClaimedSources` so it stays inspectable without being fact.
/// Refine passes `false`: the value it inherits is a previous build's system
/// stamp, not a fresh model claim.
pub(crate) fn stamp_source_provenance(
    document: &mut Value,
    sources: Value,
    record_model_claim: bool,
) {
    let Some(provenance) = provenance_object(document) else {
        return;
    };
    let claimed = provenance.get("sources").cloned();
    if record_model_claim {
        if let Some(claimed) = claimed.filter(|claimed| *claimed != sources) {
            provenance.insert("modelClaimedSources".to_string(), claimed);
        }
    }
    provenance.insert("sources".to_string(), sources);
}

fn provenance_object(document: &mut Value) -> Option<&mut Map<String, Value>> {
    let root = document.as_object_mut()?;
    if !root.get("provenance").is_some_and(Value::is_object) {
        root.insert("provenance".to_string(), json!({}));
    }
    root.get_mut("provenance")?.as_object_mut()
}

/// Replace model claims and inherited identities with this build's host stamp.
/// A failed capture must leave the source unknown rather than reuse a hash.
pub(crate) fn stamp_source_tree_hash(document: &mut Value, captured: Option<&str>) {
    let Some(provenance) = provenance_object(document) else {
        return;
    };
    provenance.remove("treeHash");
    if let Some(hash) = captured {
        provenance.insert("treeHash".to_string(), json!(hash));
    }
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
    fn source_identity_replaces_model_claims_without_verifying_context_claims() {
        let mut document = json!({"provenance":{"treeHash":"model-claim"}});
        stamp_source_tree_hash(&mut document, Some("host-capture"));
        assert_eq!(document["provenance"]["treeHash"], "host-capture");
        assert!(document.get("verification").is_none());
    }

    #[test]
    fn unavailable_source_identity_removes_inherited_and_model_claims() {
        let mut document = json!({"provenance":{"treeHash":"previous-build","pipeline":"staged"}});
        stamp_source_tree_hash(&mut document, None);
        assert!(document["provenance"].get("treeHash").is_none());
        assert_eq!(document["provenance"]["pipeline"], "staged");
    }

    #[test]
    fn source_identity_creates_missing_provenance() {
        let mut document = json!({"dfd":{}});
        stamp_source_tree_hash(&mut document, Some("host-capture"));
        assert_eq!(document["provenance"]["treeHash"], "host-capture");
    }

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
        stamp_seed_lineage(&mut document, "seeded", None, Some(&previous));
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
        stamp_seed_lineage(&mut document, "fresh", None, None);
        assert_eq!(document["provenance"]["seedMode"], json!("fresh"));
        assert!(document["provenance"].get("seededFrom").is_none());
        assert!(document["provenance"].get("seedModeRequested").is_none());
    }

    #[test]
    fn a_request_that_could_not_be_honored_is_recorded_alongside_the_observed_mode() {
        let mut document = json!({});
        stamp_seed_lineage(&mut document, "fresh", Some("seeded"), None);
        assert_eq!(document["provenance"]["seedMode"], json!("fresh"));
        assert_eq!(document["provenance"]["seedModeRequested"], json!("seeded"));
    }

    #[test]
    fn non_object_document_is_left_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let mut document = json!([]);
        stamp_provenance(&mut document, temp.path(), "single");
        assert_eq!(document, json!([]));
    }

    fn system_sources() -> Value {
        json!([{"kind": "artifact", "label": "context", "status": "loaded"}])
    }

    #[test]
    fn model_claimed_sources_are_demoted_not_trusted() {
        // The observed forgery: the model echoed the untrusted-content fence
        // delimiter into the field meant to record what the build consumed.
        let mut document = json!({
            "provenance": {"sources": ["UNTRUSTED_REPO_BEGIN", "attack-surface map"]},
        });
        stamp_source_provenance(&mut document, system_sources(), true);
        assert_eq!(document["provenance"]["sources"], system_sources());
        assert_eq!(
            document["provenance"]["modelClaimedSources"],
            json!(["UNTRUSTED_REPO_BEGIN", "attack-surface map"])
        );
    }

    #[test]
    fn refine_does_not_demote_an_inherited_system_stamp() {
        let mut document = json!({"provenance": {"sources": ["stale system row"]}});
        stamp_source_provenance(&mut document, system_sources(), false);
        assert_eq!(document["provenance"]["sources"], system_sources());
        assert!(document["provenance"].get("modelClaimedSources").is_none());
    }

    #[test]
    fn matching_claim_is_not_recorded_as_a_separate_row() {
        let mut document = json!({"provenance": {"sources": system_sources()}});
        stamp_source_provenance(&mut document, system_sources(), true);
        assert!(document["provenance"].get("modelClaimedSources").is_none());
    }

    #[test]
    fn absent_provenance_is_created_with_system_sources() {
        let mut document = json!({});
        stamp_source_provenance(&mut document, system_sources(), true);
        assert_eq!(document["provenance"]["sources"], system_sources());
        assert!(document["provenance"].get("modelClaimedSources").is_none());
    }
}
