use super::*;

#[test]
fn text_prefixes_keep_utf8_and_identities_are_never_shortened() {
    let mut projection = Projection::default();
    let row = json!({"name":"文".repeat(MAX_TEXT_BYTES),"id":"i".repeat(MAX_ID_BYTES+1)});
    let text = projection.text(&row, "name").unwrap();
    assert!(text.len() <= MAX_TEXT_BYTES);
    assert!(row["name"].as_str().unwrap().starts_with(&text));
    assert!(projection.identity(&row, "id").is_none());
    assert_eq!(projection.truncated_text_fields, 1);
    assert_eq!(projection.omitted_values, 1);
    assert!(projection.is_partial());
}

#[test]
fn references_are_deduplicated_and_overflow_is_disclosed() {
    let mut projection = Projection::default();
    let row = json!({"refs":vec!["node";MAX_REFERENCES + 7]});
    assert_eq!(projection.references(&row, "refs"), vec!["node"]);
    assert_eq!(projection.duplicate_references, MAX_REFERENCES - 1);
    assert_eq!(projection.omitted_values, 7);
}

#[test]
fn element_index_borrows_bounded_rows_without_copying_nested_fields() {
    let rows = (0..MAX_ELEMENTS + 3)
        .map(|i| json!({"id":format!("n{i}"),"unused":{"nested":["ignored"]}}))
        .collect::<Vec<_>>();
    let mut projection = Projection::default();
    let elements = projection.elements(Some(&rows));
    assert_eq!(elements.len(), MAX_ELEMENTS);
    assert!(std::ptr::eq(elements["n0"], &rows[0]));
    assert_eq!(projection.omitted_elements, 3);
    assert!(projection.is_partial());
}

#[test]
fn escaped_bytes_count_toward_card_capacity_without_retaining_a_buffer() {
    let mut projection = Projection::default();
    let card = json!({"text":"\u{0000}".repeat(MAX_CARD_BYTES / 2)});
    assert!(!projection.admit(&card));
    assert_eq!(projection.retained_card_bytes, 0);
    assert_eq!(projection.omitted_lead_cards, 1);
}

#[test]
fn cumulative_card_capacity_cannot_be_exceeded() {
    let mut projection = Projection::default();
    let card = json!({"text":"a".repeat(MAX_CARD_BYTES / 2)});
    let mut retained = 0;
    for _ in 0..256 {
        retained += usize::from(projection.admit(&card));
    }
    assert!(retained > 0 && retained < 256);
    assert!(projection.retained_card_bytes <= MAX_CARDS_BYTES);
    assert_eq!(projection.omitted_lead_cards, 256 - retained);
}

#[test]
fn linked_fields_and_repetitions_cannot_expand_into_unbounded_cards() {
    let dfd = json!({"nodes":[{"id":"node","name":"a".repeat(100_000)}],
        "flows":[{"id":"flow","sourceId":"node","targetId":"node","description":"b".repeat(100_000)}]});
    let refs = [vec!["node"; 1000], vec!["flow"; 1000]].concat();
    let threats = vec![
        json!({"id":"T1","title":"Owned parser resource limits","targetElementIds":refs});
        256
    ];
    let mut projection = Projection::default();
    let cards =
        super::super::derive_leads(&threats, &dfd, &[], &|| false, &mut projection).unwrap();
    assert_eq!(cards.len(), 256);
    assert!(cards
        .iter()
        .all(|card| card["linkedNodes"].as_array().unwrap().len() == 1));
    assert!(cards
        .iter()
        .all(|card| card["linkedFlows"].as_array().unwrap().is_empty()));
    assert!(projection.is_partial());
    assert!(projection.retained_card_bytes <= MAX_CARDS_BYTES);
    assert!(serde_json::to_vec(&cards).unwrap().len() <= MAX_CARDS_BYTES);
}

#[test]
fn malformed_and_duplicate_element_ids_are_disclosed_without_changing_identity() {
    let rows = vec![
        json!({"id":"n","name":"first"}),
        json!({"id":"n","name":"last"}),
        json!({"name":"missing"}),
        json!({"id":"x".repeat(MAX_ID_BYTES+1)}),
    ];
    let mut projection = Projection::default();
    let elements = projection.elements(Some(&rows));
    assert_eq!(elements.len(), 1);
    assert_eq!(elements["n"]["name"], "last");
    assert_eq!(projection.omitted_elements, 2);
    assert_eq!(projection.duplicate_element_ids, 1);
    assert!(projection.is_partial());
}

#[test]
fn linked_flow_fields_and_endpoint_names_are_limited_before_retention() {
    let dfd = json!({"nodes":[{"id":"node","name":"文".repeat(MAX_TEXT_BYTES)}],
        "flows":[{"id":"flow","sourceId":"node","targetId":"node","description":"d".repeat(MAX_TEXT_BYTES+10)}]});
    let threats = vec![
        json!({"id":"T1","title":"Owned parser resource limits","targetElementIds":["flow","flow"]}),
    ];
    let mut projection = Projection::default();
    let cards =
        super::super::derive_leads(&threats, &dfd, &[], &|| false, &mut projection).unwrap();
    let flows = cards[0]["linkedFlows"].as_array().unwrap();
    assert_eq!(flows.len(), 1);
    for field in ["source", "target", "description"] {
        assert!(flows[0][field].as_str().unwrap().len() <= MAX_TEXT_BYTES);
    }
    assert_eq!(projection.truncated_text_fields, 3);
    assert_eq!(projection.duplicate_references, 1);
}
