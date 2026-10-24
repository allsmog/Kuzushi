use super::*;
use serde_json::json;

fn document() -> Value {
    json!({"systemContext":"Original","dfd":{"nodes":[
        {"id":"app","name":"Application","type":"process","trustZone":"internal","codeEvidence":[{"file":"app.rs","line":1}]},
        {"id":"actor / ~ literal","name":"Principal","type":"process","trustZone":"external"}],
        "flows":[{"id":"request","description":"Request","sourceId":"app","targetId":"actor / ~ literal","trustBoundaryIds":["edge"]}],
        "trustBoundaries":[{"id":"edge","name":"Network","crossingFlowIds":["request"]}]},
        "provenance":{"sourceRevision":"recorded"},"verification":{"verdict":"pass"}})
}

fn edit(pointer: &str, text: &str) -> ContextTextEdit {
    ContextTextEdit {
        pointer: pointer.into(),
        text: text.into(),
    }
}

#[test]
fn architecture_corrections_preserve_ids_evidence_source_and_unselected_fields() {
    let original = document();
    let revised = apply_context_operator_edits(
        &original,
        &[
            edit("/dfd/nodes/1/name", "Account holder"),
            edit("/dfd/nodes/1/type", "external-entity"),
            edit("/dfd/nodes/1/trustZone", "client"),
            edit("/dfd/flows/0/sourceId", "actor / ~ literal"),
            edit("/dfd/flows/0/targetId", "app"),
            edit("/dfd/trustBoundaries/0/name", "Client boundary"),
        ],
    )
    .unwrap();
    assert_eq!(revised["dfd"]["nodes"][1]["type"], "external-entity");
    assert_eq!(revised["dfd"]["flows"][0]["sourceId"], "actor / ~ literal");
    assert_eq!(
        revised["dfd"]["nodes"][1]["id"],
        original["dfd"]["nodes"][1]["id"]
    );
    for pointer in [
        "/provenance",
        "/dfd/nodes/0",
        "/dfd/flows/0/trustBoundaryIds",
        "/dfd/trustBoundaries/0/crossingFlowIds",
    ] {
        assert_eq!(
            revised.pointer(pointer),
            original.pointer(pointer),
            "{pointer}"
        );
    }
}

#[test]
fn invalid_choices_empty_names_and_multiline_zones_cannot_change_context() {
    let original = document();
    for invalid in [
        edit("/dfd/nodes/1/type", "data-flow"),
        edit("/dfd/nodes/1/type", "external_entity"),
        edit("/dfd/nodes/1/name", " "),
        edit("/dfd/nodes/1/trustZone", "client\ninternal"),
        edit("/dfd/flows/0/sourceId", "missing"),
        edit("/dfd/flows/0/targetId", "request"),
        edit("/dfd/nodes/1/id", "new-id"),
        edit("/provenance/sourceRevision", "current"),
    ] {
        assert!(apply_context_operator_edits(
            &original,
            &[edit("/systemContext", "changed"), invalid]
        )
        .is_err());
    }
    assert_eq!(original, document());
}

#[test]
fn ambiguous_node_ids_are_not_offered_as_flow_endpoints() {
    let mut original = document();
    original["dfd"]["nodes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"app","name":"Other app"}));
    let choices = node_choices(&original);
    assert_eq!(choices.len(), 1);
    assert_eq!(choices[0].value, "actor / ~ literal");
    assert!(
        apply_context_operator_edits(&original, &[edit("/dfd/flows/0/targetId", "app")]).is_err()
    );
}

#[test]
fn narration_regeneration_does_not_gain_structural_edit_access() {
    for pointer in [
        "/dfd/nodes/1/name",
        "/dfd/nodes/1/type",
        "/dfd/nodes/1/trustZone",
        "/dfd/flows/0/sourceId",
    ] {
        assert!(apply_context_text_edits(&document(), &[edit(pointer, "app")]).is_err());
    }
    let fields = context_operator_fields(&document());
    let old = context_text_fields(&document());
    assert_eq!(
        fields[..old.len()]
            .iter()
            .map(|field| field.text.clone())
            .collect::<Vec<_>>(),
        old
    );
    assert!(fields[old.len()..].iter().all(|field| !field.regeneratable));
}

#[test]
fn malformed_rows_are_not_given_editable_parents() {
    let original = json!({"dfd":{"nodes":[null,"text"],"flows":[false],"trustBoundaries":[9]}});
    assert_eq!(context_operator_fields(&original).len(), 1);
    assert!(
        apply_context_operator_edits(&original, &[edit("/dfd/nodes/0/type", "process")]).is_err()
    );
}

#[test]
fn unchanged_legacy_values_remain_readable_without_an_implicit_repair() {
    let mut original = document();
    original["dfd"]["nodes"][1]["type"] = json!("legacy-role");
    let revised =
        apply_context_operator_edits(&original, &[edit("/systemContext", "Operator overview")])
            .unwrap();
    assert_eq!(revised["dfd"], original["dfd"]);
    assert!(apply_context_operator_edits(&original, &[]).is_err());
    let role = edit("/dfd/nodes/1/type", "external-entity");
    assert!(apply_context_operator_edits(&original, &[role.clone(), role]).is_err());
}

#[test]
fn endpoint_choices_preserve_literal_ids_and_exclude_values_outside_edit_limits() {
    let mut original = document();
    let nodes = original["dfd"]["nodes"].as_array_mut().unwrap();
    for id in [
        String::new(),
        "line\nbreak".into(),
        "x".repeat(MAX_CONTEXT_EDIT_BYTES + 1),
    ] {
        nodes.push(json!({"id":id,"name":"Unsupported endpoint"}));
    }
    assert_eq!(node_choices(&original).len(), 2);
    assert!(node_choices(&original)
        .iter()
        .any(|choice| choice.value == "actor / ~ literal"));
}
