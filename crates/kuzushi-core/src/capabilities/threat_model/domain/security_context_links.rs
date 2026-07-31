use serde_json::Value;
use std::collections::BTreeSet;

const DFD_COLLECTIONS: &[(&str, &str)] = &[
    ("node", "/dfd/nodes"),
    ("flow", "/dfd/flows"),
    ("trust boundary", "/dfd/trustBoundaries"),
];

const SECURITY_COLLECTIONS: &[(&str, &str)] = &[
    ("entry point", "/attackSurface/entryPoints"),
    ("role gate", "/attackSurface/roleGates"),
    ("external sink", "/attackSurface/externalSinks"),
    ("trusted caller", "/attackSurface/trustedCallers"),
    ("asset", "/assets"),
    ("threat", "/threats"),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityContextLinkReport {
    pub dfd_element_count: usize,
    pub linked_row_count: usize,
    pub errors: Vec<String>,
}

impl SecurityContextLinkReport {
    pub fn is_complete(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn security_context_link_report(document: &Value) -> SecurityContextLinkReport {
    let mut report = SecurityContextLinkReport::default();
    let dfd_ids = collect_dfd_ids(document, &mut report);
    validate_dfd_references(document, &dfd_ids, &mut report);
    validate_security_rows(document, &dfd_ids, &mut report);
    report
}

pub(crate) fn require_complete_security_context_links(document: &Value) -> anyhow::Result<()> {
    let report = security_context_link_report(document);
    if report.is_complete() {
        return Ok(());
    }
    anyhow::bail!(
        "threat model security-context links are invalid: {}",
        report.errors.join("; ")
    )
}

fn collect_dfd_ids(document: &Value, report: &mut SecurityContextLinkReport) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for (kind, pointer) in DFD_COLLECTIONS {
        for (index, row) in rows_at(document, pointer).enumerate() {
            let path = format!("{pointer}/{index}");
            let Some(id) = required_id(row, &path, kind, report) else {
                continue;
            };
            if !ids.insert(id.clone()) {
                report
                    .errors
                    .push(format!("{path}.id duplicates DFD id `{id}`"));
            }
        }
    }
    report.dfd_element_count = ids.len();
    ids
}

fn required_id(
    row: &Value,
    path: &str,
    kind: &str,
    report: &mut SecurityContextLinkReport,
) -> Option<String> {
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty());
    if id.is_none() {
        report
            .errors
            .push(format!("{path} {kind} requires a non-empty id"));
    }
    id.map(ToString::to_string)
}

fn validate_dfd_references(
    document: &Value,
    dfd_ids: &BTreeSet<String>,
    report: &mut SecurityContextLinkReport,
) {
    let node_ids = ids_at(document, "/dfd/nodes");
    let flow_ids = ids_at(document, "/dfd/flows");
    let boundary_ids = ids_at(document, "/dfd/trustBoundaries");
    validate_flow_references(document, &node_ids, &boundary_ids, report);
    validate_boundary_references(document, &flow_ids, report);
    if dfd_ids.is_empty() {
        report
            .errors
            .push("/dfd requires at least one identified element".to_string());
    }
}

fn validate_flow_references(
    document: &Value,
    node_ids: &BTreeSet<String>,
    boundary_ids: &BTreeSet<String>,
    report: &mut SecurityContextLinkReport,
) {
    for (index, flow) in rows_at(document, "/dfd/flows").enumerate() {
        let path = format!("/dfd/flows/{index}");
        validate_scalar_ref(flow, "sourceId", node_ids, &path, report);
        validate_scalar_ref(flow, "targetId", node_ids, &path, report);
        validate_array_refs(flow, "trustBoundaryIds", boundary_ids, &path, false, report);
    }
}

fn validate_boundary_references(
    document: &Value,
    flow_ids: &BTreeSet<String>,
    report: &mut SecurityContextLinkReport,
) {
    for (index, boundary) in rows_at(document, "/dfd/trustBoundaries").enumerate() {
        validate_array_refs(
            boundary,
            "crossingFlowIds",
            flow_ids,
            &format!("/dfd/trustBoundaries/{index}"),
            false,
            report,
        );
    }
}

fn validate_security_rows(
    document: &Value,
    dfd_ids: &BTreeSet<String>,
    report: &mut SecurityContextLinkReport,
) {
    let mut row_ids = BTreeSet::new();
    for (kind, pointer) in SECURITY_COLLECTIONS {
        for (index, row) in rows_at(document, pointer).enumerate() {
            let path = format!("{pointer}/{index}");
            validate_security_row(row, kind, &path, dfd_ids, &mut row_ids, report);
            report.linked_row_count += 1;
        }
    }
}

fn validate_security_row(
    row: &Value,
    kind: &str,
    path: &str,
    dfd_ids: &BTreeSet<String>,
    row_ids: &mut BTreeSet<String>,
    report: &mut SecurityContextLinkReport,
) {
    let id = required_id(row, path, kind, report);
    register_security_row_id(id, path, row_ids, report);
    validate_array_refs(row, "targetElementIds", dfd_ids, path, true, report);
}

fn register_security_row_id(
    id: Option<String>,
    path: &str,
    row_ids: &mut BTreeSet<String>,
    report: &mut SecurityContextLinkReport,
) {
    let Some(id) = id else {
        return;
    };
    if !row_ids.insert(id.clone()) {
        report
            .errors
            .push(format!("{path}.id duplicates security-context id `{id}`"));
    }
}

fn validate_scalar_ref(
    row: &Value,
    field: &str,
    valid_ids: &BTreeSet<String>,
    path: &str,
    report: &mut SecurityContextLinkReport,
) {
    let value = row.get(field).and_then(Value::as_str).map(str::trim);
    match value {
        Some(id) if valid_ids.contains(id) => {}
        Some(id) if !id.is_empty() => report
            .errors
            .push(format!("{path}.{field} references unknown id `{id}`")),
        _ => report.errors.push(format!("{path}.{field} is required")),
    }
}

fn validate_array_refs(
    row: &Value,
    field: &str,
    valid_ids: &BTreeSet<String>,
    path: &str,
    required: bool,
    report: &mut SecurityContextLinkReport,
) {
    let Some(values) = row.get(field).and_then(Value::as_array) else {
        if required {
            report.errors.push(format!("{path}.{field} is required"));
        }
        return;
    };
    if required && values.is_empty() {
        report
            .errors
            .push(format!("{path}.{field} requires at least one DFD id"));
    }
    for value in values {
        validate_array_ref(value, field, valid_ids, path, report);
    }
}

fn validate_array_ref(
    value: &Value,
    field: &str,
    valid_ids: &BTreeSet<String>,
    path: &str,
    report: &mut SecurityContextLinkReport,
) {
    let Some(id) = value.as_str().map(str::trim).filter(|id| !id.is_empty()) else {
        report
            .errors
            .push(format!("{path}.{field} contains a non-string or empty id"));
        return;
    };
    if !valid_ids.contains(id) {
        report
            .errors
            .push(format!("{path}.{field} references unknown DFD id `{id}`"));
    }
}

fn ids_at(document: &Value, pointer: &str) -> BTreeSet<String> {
    rows_at(document, pointer)
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect()
}

fn rows_at<'a>(document: &'a Value, pointer: &str) -> impl Iterator<Item = &'a Value> {
    document
        .pointer(pointer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn linked_document() -> Value {
        json!({
            "dfd": {
                "nodes": [
                    {"id": "user"},
                    {"id": "api"}
                ],
                "flows": [{
                    "id": "request",
                    "sourceId": "user",
                    "targetId": "api",
                    "trustBoundaryIds": ["edge"]
                }],
                "trustBoundaries": [{
                    "id": "edge",
                    "crossingFlowIds": ["request"]
                }]
            },
            "attackSurface": {
                "entryPoints": [{
                    "id": "AS-route",
                    "targetElementIds": ["api"]
                }],
                "roleGates": [{
                    "id": "RG-auth",
                    "targetElementIds": ["request", "edge"]
                }]
            },
            "assets": [{"id": "A-token", "targetElementIds": ["api"]}],
            "threats": [{"id": "T-1", "targetElementIds": ["request"]}]
        })
    }

    #[test]
    fn complete_links_accept_every_dfd_element_kind() {
        let report = security_context_link_report(&linked_document());

        assert!(report.is_complete(), "{:?}", report.errors);
        assert_eq!(report.dfd_element_count, 4);
        assert_eq!(report.linked_row_count, 4);
    }

    #[test]
    fn missing_and_unknown_links_are_reported_with_paths() {
        let mut document = linked_document();
        document["attackSurface"]["entryPoints"][0]
            .as_object_mut()
            .unwrap()
            .remove("targetElementIds");
        document["threats"][0]["targetElementIds"] = json!(["missing"]);

        let report = security_context_link_report(&document);

        assert!(report
            .errors
            .iter()
            .any(|error| error == "/attackSurface/entryPoints/0.targetElementIds is required"));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("unknown DFD id `missing`")));
    }

    #[test]
    fn duplicate_dfd_ids_and_broken_topology_are_rejected() {
        let mut document = linked_document();
        document["dfd"]["flows"][0]["id"] = json!("api");
        document["dfd"]["flows"][0]["sourceId"] = json!("missing");

        let report = security_context_link_report(&document);

        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("duplicates DFD id `api`")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("sourceId references unknown id `missing`")));
    }
}
