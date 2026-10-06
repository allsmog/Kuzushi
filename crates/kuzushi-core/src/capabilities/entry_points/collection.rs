use super::domain::EntryPointRecord;
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

pub(super) fn collect_entry_points(snapshot: &Value) -> Result<Vec<EntryPointRecord>> {
    let rows = attack_surface_rows(snapshot)?;
    anyhow::ensure!(
        !rows
            .iter()
            .any(crate::workspace::rust_surface_policy::is_legacy_rust_row),
        crate::workspace::rust_surface_policy::REBUILD_RUST_SURFACES
    );
    anyhow::ensure!(
        !rows
            .iter()
            .any(crate::workspace::python_surface_policy::is_legacy_python_http_row),
        crate::workspace::python_surface_policy::REBUILD_PYTHON_SURFACES
    );
    rows.iter()
        .map(normalize_entry_point)
        .filter_map(Result::transpose)
        .collect()
}

fn attack_surface_rows(snapshot: &Value) -> Result<&Vec<Value>> {
    let map = snapshot
        .get("attackSurfaceMap")
        .and_then(Value::as_object)
        .context("context snapshot has no attackSurfaceMap object")?;
    if let Some(rows) = map.get("surfaces") {
        return rows
            .as_array()
            .context("context snapshot attackSurfaceMap.surfaces is not an array");
    }
    map.get("nodes")
        .context("context snapshot attackSurfaceMap has neither surfaces nor legacy nodes")?
        .as_array()
        .context("context snapshot attackSurfaceMap.nodes is not an array")
}

fn normalize_entry_point(node: &Value) -> Result<Option<EntryPointRecord>> {
    let Some(mut fields) = recognized_entry_point_fields(node) else {
        return Ok(None);
    };
    fill_required_surface_fields(&mut fields);
    normalize_risk(&mut fields)?;
    let mut record: EntryPointRecord = serde_json::from_value(Value::Object(fields))
        .context("recognized entry-point row violates the typed surface contract")?;
    anyhow::ensure!(
        !record.surface.path.trim().is_empty(),
        "recognized entry-point row has no source path"
    );
    let canonical_id = crate::workspace::attack_surface::attack_surface_id(&record.surface);
    anyhow::ensure!(
        record.surface.id.trim().is_empty() || record.surface.id == canonical_id,
        "recognized entry-point row has a non-canonical stable id"
    );
    record.surface.id = canonical_id;
    Ok(Some(record))
}

fn recognized_entry_point_fields(node: &Value) -> Option<Map<String, Value>> {
    let mut fields = node.as_object()?.clone();
    let kind = fields.get("kind")?.as_str()?;
    fields.insert("kind".to_string(), json!(canonical_entry_point_kind(kind)?));
    Some(fields)
}

fn normalize_risk(fields: &mut Map<String, Value>) -> Result<()> {
    if fields.get("risk").is_none_or(Value::is_null) {
        fields.insert("risk".to_string(), json!({}));
    }
    let risk = fields
        .get_mut("risk")
        .and_then(Value::as_object_mut)
        .context("recognized entry-point row has a non-object risk")?;
    let score = risk.get("score").and_then(Value::as_u64).unwrap_or(0);
    risk.entry("rank".to_string()).or_insert(json!(0));
    risk.entry("score".to_string()).or_insert(json!(0));
    risk.entry("tier".to_string())
        .or_insert(json!(risk_tier(score)));
    risk.entry("reasons".to_string()).or_insert(json!([]));
    Ok(())
}

fn risk_tier(score: u64) -> &'static str {
    match score {
        90.. => "critical",
        75..=89 => "high",
        50..=74 => "medium",
        _ => "low",
    }
}

fn fill_required_surface_fields(fields: &mut Map<String, Value>) {
    let path = fields
        .get("path")
        .or_else(|| fields.get("source"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let title = first_text(fields, &["title", "handler", "route", "path"]);
    insert_surface_identity(fields, &path, &title);
    let location = entry_point_location(fields);
    fields.insert("name".to_string(), json!(title));
    fields.insert("location".to_string(), location);
}

fn insert_surface_identity(fields: &mut Map<String, Value>, path: &str, title: &str) {
    fields.entry("id".to_string()).or_insert(json!(""));
    fields.entry("path".to_string()).or_insert(json!(path));
    fields.entry("language".to_string()).or_insert_with(|| {
        json!(crate::workspace::attack_surface::language_from_path(path).unwrap_or("Unknown"))
    });
    fields.entry("title".to_string()).or_insert(json!(title));
    fields.entry("evidence".to_string()).or_insert(json!(title));
}

fn first_text(fields: &Map<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| fields.get(*key).and_then(Value::as_str))
        .unwrap_or("entry point")
        .to_string()
}

fn entry_point_location(fields: &Map<String, Value>) -> Value {
    let Some(path) = fields.get("path").and_then(Value::as_str) else {
        return Value::Null;
    };
    fields
        .get("line")
        .and_then(Value::as_u64)
        .map_or_else(|| json!(path), |line| json!(format!("{path}:{line}")))
}

fn canonical_entry_point_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "http-route" | "http_route" => Some("http_route"),
        "rpc-endpoint" | "rpc_endpoint" | "rpc-handler" | "rpc_handler" | "websocket"
        | "graphql-resolver" => Some("rpc_handler"),
        "cli-entrypoint" | "cli_entrypoint" => Some("cli_entrypoint"),
        "scheduled-job" | "background-job" | "background_job" | "message-consumer" => {
            Some("background_job")
        }
        "external-service-client" | "external_service_client" => Some("external_service_client"),
        "deserialization-point" | "deserialization_point" => Some("deserialization_point"),
        "file-upload-parse-path" | "file_upload_parse_path" => Some("file_upload_parse_path"),
        _ => None,
    }
}
