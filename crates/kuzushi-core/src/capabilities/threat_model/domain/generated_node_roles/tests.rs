use super::*;

fn document(role: Value) -> Value {
    json!({"dfd":{"nodes":[{"id":"app","type":role}],"flows":[],"trustBoundaries":[]}})
}

#[test]
fn generated_node_roles_accept_known_case_and_separator_aliases() {
    for role in [
        "process",
        "PROCESS",
        "external-entity",
        "externalEntity",
        "external_entity",
        "external",
        "data-store",
        "dataStore",
        "data_store",
        "datastore",
    ] {
        require_generated_node_roles(&document(json!(role))).unwrap();
    }
}

#[test]
fn generated_node_roles_reject_unknown_types_before_compatibility_normalization() {
    for role in ["data-type", "service", "", "externalEntity ", " data-store"] {
        let raw = document(json!(role));
        let before = raw.clone();
        let error = require_generated_node_roles(&raw).unwrap_err().to_string();
        assert!(error.contains("/dfd/nodes/0/type"), "{error}");
        assert!(
            error.contains("Unsupported generated DFD node role"),
            "{error}"
        );
        assert_eq!(raw, before);
    }
}

#[test]
fn generated_node_roles_cannot_drop_a_flow_stored_as_a_node() {
    for role in ["data-flow", "dataFlow", "data_flow"] {
        let error = require_generated_node_roles(&document(json!(role)))
            .unwrap_err()
            .to_string();
        assert!(error.contains("Put flows in dfd.flows"), "{error}");
    }
}

#[test]
fn generated_node_roles_do_not_invent_missing_or_nontext_roles() {
    for node in [
        json!({"id":"app"}),
        json!({"id":"app","type":null}),
        json!({"id":"app","type":42}),
        json!("not an object"),
    ] {
        let raw = json!({"dfd":{"nodes":[node]}});
        let error = require_generated_node_roles(&raw).unwrap_err().to_string();
        assert!(error.contains("/dfd/nodes/0/type"), "{error}");
        assert!(error.contains("requires a text role"), "{error}");
    }
}

#[test]
fn generated_node_roles_validate_the_supported_elements_alias() {
    let raw = json!({"dfd":{"elements":[{"id":"app","type":"unknown"}]}});
    let error = require_generated_node_roles(&raw).unwrap_err().to_string();
    assert!(error.contains("/dfd/elements/0/type"), "{error}");
}

#[test]
fn generated_node_roles_bound_and_escape_rejected_role_labels() {
    let role = format!("invalid\n\u{1b}[2J{}", "α".repeat(1024));
    let error = require_generated_node_roles(&document(json!(role)))
        .unwrap_err()
        .to_string();
    assert!(error.len() < 512, "{error}");
    assert!(!error.contains('\u{1b}'));
    assert!(error.contains("\\n") && error.contains("…"));
}
