use super::*;

#[test]
fn preview_is_the_existing_execution_digest_with_an_exact_hash() {
    let document = json!({"systemContext":"Owned operator overview", "threats":[{"title":"Owned source review","severity":"low"}],"dfd":{"nodes":[{"id":"owned","name":"Owned application"}]}});
    let preview = build(&document);
    assert_eq!(preview["schemaVersion"], 1);
    let expected =
        crate::capabilities::agentic_sast::render_threat_model_digest(&document).unwrap();
    assert_eq!(preview["text"], expected);
    assert_eq!(
        preview["sha256"],
        crate::options::prompt_content_sha256(&expected)
    );
    assert!(expected.contains("Owned operator overview"));
}

#[test]
fn item_and_unicode_lesson_omissions_are_disclosed_without_rewriting_the_digest() {
    let lesson = format!("{} tail omitted", "界".repeat(2048));
    let document = json!({"threats":vec![json!({"title":"Owned observation"});13],"reviewedLessons":[{"id":"owned","revision":1,"content":{"title":"Owned lesson","text":lesson,"applicability":"Review only","limitations":"Synthetic owned example"}}]});
    let preview = build(&document);
    let notices = preview["omissions"].to_string();
    assert!(notices.contains("first 12 of 13"));
    assert!(notices.contains("first 2048 of 2061 characters"));
    let text = preview["text"].as_str().unwrap();
    assert!(text.contains(&"界".repeat(2048)));
    assert!(!text.contains("tail omitted"));
    assert_eq!(
        preview["text"],
        crate::capabilities::agentic_sast::render_threat_model_digest(&document).unwrap()
    );
}

#[test]
fn an_empty_digest_is_explicit_and_never_filled_from_unselected_fields() {
    let preview = build(&json!({"title":"Saved metadata without digest sections"}));
    assert!(preview["text"].is_null());
    assert!(preview["sha256"].is_null());
    assert_eq!(preview["omissions"], json!([]));
}

#[test]
fn overview_projection_is_bounded_and_its_unicode_omission_is_exact() {
    let original = json!({"systemContext":format!("{}OMITTED_TAIL", "界".repeat(200))});
    let preview = build(&original);
    let text = preview["text"].as_str().unwrap();
    assert!(text.contains("System overview:"));
    assert!(text.contains(&"界".repeat(200)));
    assert!(!text.contains("OMITTED_TAIL"));
    assert!(preview["omissions"]
        .to_string()
        .contains("System overview: first 200 of 212 characters; 12 omitted."));
    assert_eq!(
        preview["sha256"],
        crate::options::prompt_content_sha256(text)
    );
    assert!(original["systemContext"]
        .as_str()
        .unwrap()
        .ends_with("OMITTED_TAIL"));
}

#[test]
fn every_capped_ordinary_field_discloses_its_unicode_cut() {
    let long = format!("{}OMITTED_FIELD_TAIL", "界".repeat(200));
    let cases = [
        ("/threats/0/title", "Threat 1 title"),
        ("/threats/0/severity", "Threat 1 severity"),
        ("/threats/0/relatedCwe", "Threat 1 relatedCwe"),
        ("/attackSurface/entryPoints/0/name", "Entry point 1 name"),
        (
            "/attackSurface/entryPoints/0/trustZone",
            "Entry point 1 trustZone",
        ),
        (
            "/attackSurface/entryPoints/0/evidence",
            "Entry point 1 evidence",
        ),
        (
            "/attackSurface/externalSinks/0/name",
            "External sink 1 name",
        ),
        (
            "/attackSurface/externalSinks/0/category",
            "External sink 1 category",
        ),
        ("/dfd/nodes/0/name", "Component 1 name"),
        ("/dfd/nodes/0/trustZone", "Component 1 trustZone"),
        ("/dfd/nodes/0/description", "Component 1 description"),
        ("/dfd/flows/0/sourceId", "Data flow 1 sourceId"),
        ("/dfd/flows/0/targetId", "Data flow 1 targetId"),
        ("/dfd/flows/0/description", "Data flow 1 description"),
        ("/dfd/trustBoundaries/0/name", "Trust boundary 1 name"),
        (
            "/dfd/trustBoundaries/0/description",
            "Trust boundary 1 description",
        ),
        ("/openQuestions/0", "Open question 1"),
    ];
    for (pointer, label) in cases {
        let mut document = field_document();
        *document.pointer_mut(pointer).unwrap() = json!(long);
        let preview = build(&document);
        assert!(
            preview["omissions"].to_string().contains(&format!(
                "{label}: first 200 of 218 characters; 18 omitted."
            )),
            "{pointer}: {preview}"
        );
        assert!(
            !preview["text"]
                .as_str()
                .unwrap()
                .contains("OMITTED_FIELD_TAIL"),
            "{pointer}"
        );
        assert!(document
            .pointer(pointer)
            .unwrap()
            .as_str()
            .unwrap()
            .ends_with("OMITTED_FIELD_TAIL"));
    }
}

#[test]
fn field_selection_preserves_fallbacks_trim_and_joined_arrays() {
    let document = json!({"threats":[{"title":" ","description":format!("  {} tail  ","界".repeat(200)),"id":"unused fallback", "affectedFiles":["a".repeat(150),false,"b".repeat(75)]}]});
    let preview = build(&document);
    let notices = preview["omissions"].to_string();
    assert!(notices.contains("Threat 1 description: first 200 of 205 characters; 5 omitted."));
    assert!(notices.contains("Threat 1 affectedFiles: first 200 of 227 characters; 27 omitted."));
    let digest = preview["text"].as_str().unwrap();
    assert!(digest.contains(&format!("[unrated] {}...", "界".repeat(200))));
    assert!(!digest.contains("unused fallback"));
}

#[test]
fn unselected_aliases_and_unrenderable_rows_do_not_claim_field_truncation() {
    let long = "x".repeat(300);
    let document = json!({"threats":[{"title":"Selected title","description":long}],"dfd":{"nodes":[{"description":long}],"flows":[{"sourceId":"app","description":long}],"trustBoundaries":[{"description":long}]}});
    let preview = build(&document);
    assert_eq!(preview["omissions"], json!([]));
    assert_eq!(
        preview["text"],
        "Modeled threats:\n- [unrated] Selected title"
    );
}

#[test]
fn omitted_items_do_not_also_claim_their_fields_were_partly_included() {
    let mut document = field_document();
    let threats = document["threats"].as_array_mut().unwrap();
    threats.resize(12, json!({"title":"Included title"}));
    threats.push(json!({"title":"x".repeat(300)}));
    let preview = build(&document);
    let notices = preview["omissions"].to_string();
    assert!(notices.contains("Threats: first 12 of 13 items; 1 omitted."));
    assert!(!notices.contains("Threat 13"));
}

#[test]
fn variant_limits_disclose_the_flattened_selection_and_raw_code_cut() {
    let code = format!("{}OMITTED_CODE_TAIL", "界".repeat(200));
    let patterns = (0..13).map(|index| json!({"title":format!("Owned pattern {index}"),"location":"owned.txt:1","code":code})).collect::<Vec<_>>();
    let preview = build(
        &json!({"threats":[{"title":"Owned historical guidance","variantPatterns":patterns}]}),
    );
    let notices = preview["omissions"].to_string();
    assert!(notices.contains("Variant patterns: first 12 of 13 items; 1 omitted."));
    assert!(notices.contains("Variant pattern code fields 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 (each): first 200 of 217 characters; 17 omitted."));
    assert!(!notices.contains("code fields 13"));
    assert!(!preview["text"]
        .as_str()
        .unwrap()
        .contains("OMITTED_CODE_TAIL"));
    assert!(!preview["text"]
        .as_str()
        .unwrap()
        .contains("Owned pattern 12"));
}

#[test]
fn variants_on_a_threat_outside_the_threat_limit_still_match_execution() {
    let mut threats = vec![json!({"title":"Selected threat"}); 12];
    threats.push(json!({"title":"OMITTED_THREAT_TITLE","variantPatterns":[{"title":"Included historical pattern","code":"x".repeat(201)}]}));
    let preview = build(&json!({"threats":threats}));
    assert!(preview["text"]
        .as_str()
        .unwrap()
        .contains("Included historical pattern"));
    assert!(!preview["text"]
        .as_str()
        .unwrap()
        .contains("OMITTED_THREAT_TITLE"));
    assert!(preview["omissions"]
        .to_string()
        .contains("Variant pattern code fields 1 (each): first 200 of 201 characters; 1 omitted."));
}

#[test]
fn uncapped_variant_labels_are_retained_without_a_false_field_limit() {
    let title = "x".repeat(201);
    let preview = build(
        &json!({"threats":[{"variantPatterns":[{"title":title,"location":title,"code":"small"}]}]}),
    );
    assert_eq!(preview["omissions"], json!([]));
    assert!(preview["text"].as_str().unwrap().contains(&title));
}

#[test]
fn grouped_pattern_cuts_keep_distinct_lengths_and_exact_indexes() {
    let patterns = [201, 203, 201, 200, 0].map(|count| json!({"code":"x".repeat(count)}));
    let preview = build(&json!({"threats":[{"variantPatterns":patterns}]}));
    let notices = preview["omissions"].as_array().unwrap();
    assert_eq!(notices.len(), 2);
    assert!(notices.contains(&json!(
        "Variant pattern code fields 1, 3 (each): first 200 of 201 characters; 1 omitted."
    )));
    assert!(notices.contains(&json!(
        "Variant pattern code fields 2 (each): first 200 of 203 characters; 3 omitted."
    )));
}

fn field_document() -> Value {
    json!({"threats":[{"title":"Owned claim","severity":"low","relatedCwe":"unclassified"}],
        "attackSurface":{"entryPoints":[{"name":"Input","trustZone":"local","evidence":"owned.txt:1"}],"externalSinks":[{"name":"Output","category":"display"}]},
        "dfd":{"nodes":[{"name":"Owned application","trustZone":"local","description":"Read text"}],"flows":[{"sourceId":"app","targetId":"terminal","description":"Print text"}],"trustBoundaries":[{"name":"Local operator","description":"Supplies text"}]},"openQuestions":["Owned question"]})
}
