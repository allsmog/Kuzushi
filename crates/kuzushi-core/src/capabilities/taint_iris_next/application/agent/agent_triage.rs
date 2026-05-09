use super::*;

pub(in crate::capabilities::taint_iris_next) fn normalize_taint_iris_next_triage(
    items: Vec<Value>,
) -> Vec<Value> {
    items
        .into_iter()
        .filter_map(|item| {
            let Value::Object(object) = item else {
                return None;
            };
            let cwe = read_object_string(&object, &["cwe"])?;
            Some(json!({
                "status": read_object_string(&object, &["status"]).unwrap_or_else(|| "candidate".to_string()),
                "cwe": normalize_taint_next_cwe(&cwe),
                "evidenceLevel": read_object_string(&object, &["evidenceLevel", "evidence_level"]).unwrap_or_else(|| "candidate".to_string()),
                "rationale": read_object_string(&object, &["rationale"]).unwrap_or_default(),
                "filePath": read_object_string(&object, &["filePath", "file_path"]),
                "line": read_object_u64(&object, &["line", "startLine", "start_line"]).unwrap_or(1),
                "catalogSignals": read_object_string_array(&object, &["catalogSignals", "catalog_signals"]),
            }))
        })
        .collect()
}
