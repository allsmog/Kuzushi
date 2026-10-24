use super::*;

#[test]
fn normalize_dfd_canonicalizes_camelcase_node_types() {
    let mut dfd = json!({
        "nodes": [
            {"id": "n1", "type": "externalEntity", "name": "Client"},
            {"id": "n2", "type": "dataStore", "name": "Tablespace"},
            {"id": "n3", "type": "process", "name": "Server"},
            {"id": "f1", "type": "data-flow", "name": "Dropped flow"},
        ],
        "flows": [],
        "trustBoundaries": [],
    });

    normalize_dfd(&mut dfd);

    let types = dfd
        .get("nodes")
        .and_then(Value::as_array)
        .expect("nodes array")
        .iter()
        .map(|node| node.get("type").and_then(Value::as_str).unwrap_or(""))
        .collect::<Vec<_>>();

    assert_eq!(types, vec!["external-entity", "data-store", "process"]);
}

fn mixed_threat_enum_document() -> Value {
    json!({"threats": [
        {
            "id": "T-1",
            "title": "upload tamper",
            "actor": "unauthenticated remote attacker",
            "impact": "Critical",
            "likelihood": "high",
            "status": "wont-fix"
        },
        {
            "id": "T-2",
            "title": "novel actor",
            "actor": "sentient toaster",
            "impact": "existential",
            "likelihood": "almost certain"
        }
    ]})
}

#[test]
fn threat_enums_canonicalize_synonyms_and_keep_unknowns_verbatim() {
    let normalized = normalize_document(mixed_threat_enum_document(), "stride").expect("normalize");
    let threats = normalized["threats"].as_array().expect("threats");
    // Sorted (impact desc, likelihood desc): existential row first.
    assert_eq!(threats[0]["id"], json!("T-2"));
    assert_eq!(
        threats[0]["actor"],
        json!("sentient toaster"),
        "unknown actor stays verbatim"
    );
    assert_eq!(threats[0]["likelihood"], json!("almost_certain"));
    assert_eq!(
        threats[0]["status"],
        json!("unmitigated"),
        "missing status defaults conservatively"
    );
    let warnings = threats[0]["normalizationWarnings"]
        .as_array()
        .expect("warnings");
    assert!(warnings
        .iter()
        .any(|w| w.as_str().unwrap().contains("sentient toaster")));
    assert!(warnings
        .iter()
        .any(|w| w.as_str().unwrap().contains("missing status")));

    assert_eq!(threats[1]["actor"], json!("remote_unauth"));
    assert_eq!(threats[1]["impact"], json!("critical"));
    assert_eq!(
        threats[1]["likelihood"],
        json!("likely"),
        "legacy high maps onto the ladder"
    );
    assert_eq!(threats[1]["status"], json!("risk_accepted"));
}

#[test]
fn threats_sort_by_impact_then_likelihood_descending() {
    let document = json!({"threats": [
        {"id": "low-rare", "impact": "low", "likelihood": "rare"},
        {"id": "high-possible", "impact": "high", "likelihood": "possible"},
        {"id": "high-likely", "impact": "high", "likelihood": "likely"},
        {"id": "critical-rare", "impact": "critical", "likelihood": "rare"}
    ]});

    let normalized = normalize_document(document, "stride").expect("normalize");
    let order = normalized["threats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|threat| threat["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        order,
        vec!["critical-rare", "high-likely", "high-possible", "low-rare"]
    );
}

#[test]
fn assets_table_guarantees_shape_and_canonical_sensitivity() {
    let document = json!({
        "threats": [],
        "assets": [
            "customer backups",
            {"name": "cluster metadata", "sensitivity": "HIGH"},
            {"asset": "audit log", "sensitivity": "radioactive"},
            42
        ]
    });

    let normalized = normalize_document(document, "stride").expect("normalize");
    let assets = normalized["assets"].as_array().expect("assets array");
    assert_eq!(assets.len(), 3, "malformed row dropped");
    assert_eq!(assets[0]["asset"], json!("customer backups"));
    assert_eq!(
        assets[1]["asset"],
        json!("cluster metadata"),
        "name aliases to asset"
    );
    assert_eq!(assets[1]["sensitivity"], json!("high"));
    assert_eq!(
        assets[2]["sensitivity"],
        json!("radioactive"),
        "unknown tier stays verbatim"
    );
    let warnings = normalized["normalizationWarnings"]
        .as_array()
        .expect("doc warnings");
    assert!(warnings
        .iter()
        .any(|w| w.as_str().unwrap().contains("radioactive")));
    assert!(warnings
        .iter()
        .any(|w| w.as_str().unwrap().contains("malformed asset row")));
}

#[test]
fn missing_assets_key_normalizes_to_an_empty_table() {
    let normalized = normalize_document(json!({"threats": []}), "stride").expect("normalize");
    assert_eq!(normalized["assets"], json!([]));
}

fn mixed_mitigation_document() -> Value {
    json!({
        "threats": [],
        "recommendedMitigations": [
            "centralize upload validation",
            {
                "mitigation": "parameterize all queries",
                "threat_ids": ["T1", "T3"],
                "closes_class": "full",
                "effort": "small"
            },
            {
                "title": "rotate signing keys",
                "closesClass": "sorta",
                "effort": "XXL"
            }
        ]
    })
}

#[test]
fn recommended_mitigations_coerce_into_structured_rows() {
    let normalized = normalize_document(mixed_mitigation_document(), "stride").expect("normalize");
    let rows = normalized["recommendedMitigations"]
        .as_array()
        .expect("rows");
    assert_eq!(rows[0]["mitigation"], json!("centralize upload validation"));
    assert_eq!(rows[0]["threatIds"], json!([]));
    assert_eq!(rows[1]["mitigation"], json!("parameterize all queries"));
    assert_eq!(rows[1]["threatIds"], json!(["T1", "T3"]));
    assert_eq!(rows[1]["closesClass"], json!("yes"));
    assert_eq!(rows[1]["effort"], json!("S"));
    assert_eq!(
        rows[2]["mitigation"],
        json!("rotate signing keys"),
        "title aliases to mitigation"
    );
    assert_eq!(
        rows[2]["closesClass"],
        json!("sorta"),
        "unknown closesClass stays verbatim"
    );
    assert_eq!(
        rows[2]["effort"],
        json!("XXL"),
        "unknown effort stays verbatim"
    );
    let warnings = normalized["normalizationWarnings"]
        .as_array()
        .expect("doc warnings");
    assert!(warnings
        .iter()
        .any(|w| w.as_str().unwrap().contains("sorta")));
    assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("XXL")));
}

#[test]
fn probability_maps_onto_the_five_band_ladder() {
    assert_eq!(probability_to_likelihood(0.95), "almost_certain");
    assert_eq!(probability_to_likelihood(0.75), "likely");
    assert_eq!(probability_to_likelihood(0.5), "possible");
    assert_eq!(probability_to_likelihood(0.2), "rare");
    assert_eq!(probability_to_likelihood(0.05), "very_rare");
}

#[test]
fn system_prompt_carries_the_harness_scoring_guide() {
    let prompt = threat_model_system_prompt();
    assert!(prompt.contains("remote_unauth"));
    assert!(prompt.contains("almost_certain"));
    assert!(prompt.contains("risk_accepted"));
    assert!(prompt.contains("existential"));
    assert!(prompt.contains("residual"));
    assert!(prompt.contains("Evidence raises likelihood"));
}

#[test]
fn generated_context_rejects_unknown_node_role_without_inventing_process() {
    let document = json!({"version":"1","methodology":"stride","dfd":{
        "nodes":[{"id":"invoice","name":"Invoice record","type":"data-type","trustZone":"internal"}],
        "flows":[],"trustBoundaries":[]},"threats":[],"summary":{}});
    let error = normalize_threat_model_raw(document, "stride")
        .err()
        .expect("Unknown generated node roles must not silently become processes");
    let text = format!("{error:#}");
    assert!(text.contains("/dfd/nodes/0/type"), "{text}");
    assert!(text.contains("data-type"), "{text}");
}
