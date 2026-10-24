use super::*;
use serde_json::json;

fn document(nodes: Value) -> Value {
    json!({"dfd":{"nodes":nodes,"flows":[],"trustBoundaries":[]},"assets":[],"openQuestions":[]})
}

fn change<'a>(diff: &'a ContextDocumentDiff, id: &str, field: &str) -> &'a ContextValueDifference {
    diff.changes
        .iter()
        .find(|change| change.identity.as_deref() == Some(id) && change.field == field)
        .unwrap()
}

#[test]
fn reused_ids_reveal_types_trust_zones_endpoints_and_boundaries() {
    let mut before = document(
        json!([{"id":"client","type":"external-entity"},{"id":"app","type":"process","trustZone":"app"}]),
    );
    before["dfd"]["flows"] =
        json!([{"id":"request","sourceId":"client","targetId":"app","trustBoundaryIds":["edge"]}]);
    before["dfd"]["trustBoundaries"] =
        json!([{"id":"edge","innerZone":"app","outerZone":"public","crossingFlowIds":["request"]}]);
    let mut after = before.clone();
    after["dfd"]["nodes"][1]["type"] = json!("data-store");
    after["dfd"]["nodes"][1]["trustZone"] = json!("restricted");
    after["dfd"]["flows"][0]["targetId"] = json!("client");
    after["dfd"]["trustBoundaries"][0]["innerZone"] = json!("restricted");
    let diff = context_document_differences(&before, &after);
    assert_eq!(diff.changes.len(), 4);
    assert_eq!(
        change(&diff, "app", "/type").after,
        Some(json!("data-store"))
    );
    assert_eq!(
        change(&diff, "app", "/trustZone").before,
        Some(json!("app"))
    );
    assert_eq!(
        change(&diff, "request", "/targetId")
            .after_pointer
            .as_deref(),
        Some("/dfd/flows/0/targetId")
    );
    assert_eq!(
        change(&diff, "edge", "/innerZone").matching,
        ContextDifferenceMatching::Id
    );
}

#[test]
fn additions_and_removals_retain_complete_rows() {
    let before = document(json!([{"id":"old","extra":{"value":1}}]));
    let after = document(json!([{"id":"new","type":"process","sourceRefs":[" app /lib.py:2"]}]));
    let diff = context_document_differences(&before, &after);
    assert_eq!(diff.changes.len(), 2);
    assert_eq!(
        change(&diff, "old", "").before,
        Some(before["dfd"]["nodes"][0].clone())
    );
    assert_eq!(
        change(&diff, "new", "").after,
        Some(after["dfd"]["nodes"][0].clone())
    );
    assert!(change(&diff, "new", "").before.is_none());
    assert_eq!(
        change(&diff, "new", "").after_pointer.as_deref(),
        Some("/dfd/nodes/0")
    );
}

#[test]
fn unique_id_reordering_is_separate_from_element_content() {
    let before = document(json!([{"id":"a","type":"process"},{"id":"b","type":"process"}]));
    let after = document(json!([{"id":"b","type":"process"},{"id":"a","type":"process"}]));
    let diff = context_document_differences(&before, &after);
    assert!(diff.changes.is_empty());
    assert_eq!(diff.reordered_collections.len(), 1);
    assert_eq!(diff.reordered_collections[0].before, vec!["a", "b"]);
    assert_eq!(diff.reordered_collections[0].after, vec!["b", "a"]);
}

#[test]
fn reordered_modified_rows_keep_both_exact_document_pointers() {
    let before = document(json!([{"id":"a","type":"process"},{"id":"b","type":"process"}]));
    let after = document(json!([{"id":"b","type":"process"},{"id":"a","type":"data-store"}]));
    let diff = context_document_differences(&before, &after);
    let field = change(&diff, "a", "/type");
    assert_eq!(field.before_pointer.as_deref(), Some("/dfd/nodes/0/type"));
    assert_eq!(field.after_pointer.as_deref(), Some("/dfd/nodes/1/type"));
    assert_eq!(diff.reordered_collections.len(), 1);
}

#[test]
fn duplicate_ids_preserve_each_position_and_disclose_ambiguity() {
    let before =
        document(json!([{"id":"same","type":"process"},{"id":"same","type":"data-store"}]));
    let after = document(json!([{"id":"same","type":"external-entity"}]));
    let diff = context_document_differences(&before, &after);
    assert_eq!(diff.changes.len(), 2);
    assert!(diff
        .changes
        .iter()
        .all(|row| row.matching == ContextDifferenceMatching::AmbiguousPosition));
    assert!(diff
        .changes
        .iter()
        .any(|row| row.before_pointer.as_deref() == Some("/dfd/nodes/1") && row.after.is_none()));
    assert!(diff.reordered_collections.is_empty());
}

#[test]
fn unkeyed_questions_remain_positional_without_guessing_new_identity() {
    let before = json!({"openQuestions":["First question",{"question":"Other"}]});
    let after = json!({"openQuestions":["Changed question",{"id":"named","question":"Other"}]});
    let diff = context_document_differences(&before, &after);
    assert_eq!(diff.changes.len(), 3);
    assert_eq!(
        diff.changes
            .iter()
            .filter(|row| row.matching == ContextDifferenceMatching::Position)
            .count(),
        2
    );
    assert!(diff
        .changes
        .iter()
        .any(|row| row.identity.as_deref() == Some("named") && row.before.is_none()));
}

#[test]
fn literal_ids_and_source_paths_are_not_trimmed_or_collapsed() {
    let before = document(
        json!([{"id":" app","sourceRefs":[" app /a  b.py:1"]},{"id":"app","sourceRefs":["app/a b.py:1"]}]),
    );
    let mut after = before.clone();
    after["dfd"]["nodes"][0]["sourceRefs"] = json!(["app/a b.py:1"]);
    let diff = context_document_differences(&before, &after);
    assert_eq!(diff.changes.len(), 1);
    assert_eq!(diff.changes[0].identity.as_deref(), Some(" app"));
    assert_eq!(diff.changes[0].before, Some(json!([" app /a  b.py:1"])));
}

#[test]
fn absent_and_explicit_null_survive_json_roundtrip() {
    let before = json!({"provenance":{}});
    let after = json!({"provenance":{"unknown":null}});
    let diff = context_document_differences(&before, &after);
    let serialized = serde_json::to_value(&diff).unwrap();
    assert!(serialized["changes"][0].get("before").is_none());
    assert_eq!(serialized["changes"][0].get("after"), Some(&Value::Null));
    assert_eq!(
        serde_json::from_value::<ContextDocumentDiff>(serialized).unwrap(),
        diff
    );
    assert_eq!(diff.changes[0].section, ContextDifferenceSection::Inputs);
}

#[test]
fn changed_unknown_fields_keep_escaped_json_pointers_and_full_arrays() {
    let before = json!({"extra":{"a/b~c":[1,2]}});
    let after = json!({"extra":{"a/b~c":[2,1]}});
    let diff = context_document_differences(&before, &after);
    assert_eq!(diff.changes.len(), 1);
    assert_eq!(
        diff.changes[0].after_pointer.as_deref(),
        Some("/extra/a~1b~0c")
    );
    assert_eq!(diff.changes[0].before, Some(json!([1, 2])));
    assert_eq!(diff.changes[0].after, Some(json!([2, 1])));
}

#[test]
fn invalid_or_missing_collection_shapes_are_not_zero_rows() {
    let before = json!({"dfd":{"nodes":null}});
    let after = json!({"dfd":{"nodes":[]}});
    let diff = context_document_differences(&before, &after);
    assert_eq!(diff.changes.len(), 1);
    assert_eq!(
        diff.changes[0].matching,
        ContextDifferenceMatching::DocumentField
    );
    assert_eq!(diff.changes[0].before, Some(Value::Null));
    assert_eq!(diff.changes[0].after, Some(json!([])));
    assert!(!context_document_differences(&json!({}), &after)
        .changes
        .is_empty());
}

#[test]
fn all_security_context_sections_and_question_fields_are_compared() {
    let before = json!({"assets":[{"id":"a","targetElementIds":["old"]}],"attackSurface":{"entryPoints":[{"id":"e","path":"before"}],"trustedCallers":[{"id":"c","role":"before"}]},"openQuestions":[{"id":"q","question":"Before?"}]});
    let mut after = before.clone();
    after["assets"][0]["targetElementIds"] = json!(["new"]);
    after["attackSurface"]["entryPoints"][0]["path"] = json!("after");
    after["attackSurface"]["trustedCallers"][0]["role"] = json!("after");
    after["openQuestions"][0]["question"] = json!("After?");
    let diff = context_document_differences(&before, &after);
    assert_eq!(diff.changes.len(), 4);
    assert_eq!(
        change(&diff, "a", "/targetElementIds").section,
        ContextDifferenceSection::SecurityContext
    );
    assert_eq!(
        change(&diff, "q", "/question").section,
        ContextDifferenceSection::Questions
    );
}

#[test]
fn contradictory_recorded_sources_remain_separate_claims() {
    let before = json!({"provenance":{"revision":"recorded-a","treeHash":"tree-a"},"targetGit":{"sha":"different-b","dirty":false}});
    let after = json!({"provenance":{"revision":"recorded-a","treeHash":"tree-c"}});
    let diff = context_document_differences(&before, &after);
    assert_eq!(
        diff.source_claims.before["/provenance/revision"],
        "recorded-a"
    );
    assert_eq!(
        diff.source_claims.before["/targetGit"]["sha"],
        "different-b"
    );
    assert!(!diff.source_claims.after.contains_key("/targetGit"));
    assert_eq!(diff.source_claims.after["/provenance/treeHash"], "tree-c");
}

#[test]
fn complete_values_and_more_than_one_hundred_changes_are_retained_without_mutation() {
    let before = document(json!((0..150)
        .map(|i| json!({"id":format!("n{i}")}))
        .collect::<Vec<_>>()));
    let mut after = before.clone();
    for row in after["dfd"]["nodes"].as_array_mut().unwrap() {
        row["description"] = json!("α".repeat(1024));
    }
    let original = before.clone();
    let candidate = after.clone();
    let diff = context_document_differences(&before, &after);
    assert_eq!(diff.changes.len(), 150);
    assert!(diff.changes.iter().all(|row| row
        .after
        .as_ref()
        .unwrap()
        .as_str()
        .unwrap()
        .chars()
        .count()
        == 1024));
    assert_eq!((before, after), (original, candidate));
}

#[test]
fn identical_documents_have_no_changes_or_order_claims() {
    let doc = document(json!([{"id":"app","type":"process"}]));
    let diff = context_document_differences(&doc, &doc);
    assert!(diff.changes.is_empty());
    assert!(diff.reordered_collections.is_empty());
}
