use super::*;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(in crate::modules) fn entry_points_module() -> BuiltinModule {
    builtin_module(
        "entry-points",
        "Entry Points",
        ModuleKind::Intel,
        "Deterministic extractor that normalizes attack-surface routes from \
         the context snapshot into a stable .kuzushi/entry-points.json.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            ),
            vec![tool_with_options(
                "entry-points:extract",
                "Extract entry points (routes, handlers, outbound clients) from the latest \
                 context snapshot. Writes .kuzushi/entry-points.json. Deterministic; no model cost.",
                vec![target_option()],
            )],
        ),
        vec![dag(
            "entry-points:extract",
            "entry-points",
            &["context:build"],
        )],
    )
}

pub(in crate::modules) fn run_entry_points_extract(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    emit_step(ctx, "tool", "extract", "entry-points start");
    let snapshot = load_context_snapshot(&target)?;
    let entry_points = collect_entry_points(&snapshot);
    let output_path = write_entry_points_json(&target, &snapshot, &entry_points)?;
    emit_step(
        ctx,
        "done",
        "extract",
        format!("entry-points wrote {} routes", entry_points.len()),
    );
    Ok(entry_points_response(&target, &output_path, &entry_points))
}

fn load_context_snapshot(target: &Path) -> Result<Value> {
    let path = target.join(".kuzushi/context-snapshot.json");
    // The snapshot ships inside the (untrusted) target: cap the read.
    let body = crate::bounded_file::read_utf8_text(&path, 64 * 1024 * 1024).with_context(|| {
        format!(
            "entry-points:extract requires .kuzushi/context-snapshot.json — \
             run `context:build` first ({} missing or unreadable)",
            path.display()
        )
    })?;
    serde_json::from_str(&body)
        .with_context(|| format!("context snapshot at {} is not valid JSON", path.display()))
}

fn collect_entry_points(snapshot: &Value) -> Vec<Value> {
    let attack_surface = snapshot.get("attackSurfaceMap").and_then(Value::as_object);
    let Some(surface) = attack_surface else {
        return Vec::new();
    };
    attack_surface_rows(surface)
        .map(|nodes| nodes.iter().filter_map(normalize_entry_point).collect())
        .unwrap_or_default()
}

fn attack_surface_rows(surface: &serde_json::Map<String, Value>) -> Option<&[Value]> {
    surface
        .get("surfaces")
        .and_then(Value::as_array)
        .or_else(|| surface.get("nodes").and_then(Value::as_array))
        .map(Vec::as_slice)
}

fn normalize_entry_point(node: &Value) -> Option<Value> {
    let fields = node.as_object()?;
    let kind = fields.get("kind").and_then(Value::as_str)?;
    if !is_entry_point_kind(kind) {
        return None;
    }
    let mut normalized = fields.clone();
    normalized
        .entry("name".to_string())
        .or_insert_with(|| entry_point_name(fields));
    normalized
        .entry("location".to_string())
        .or_insert_with(|| entry_point_location(fields));
    Some(Value::Object(normalized))
}

fn entry_point_name(fields: &serde_json::Map<String, Value>) -> Value {
    ["title", "handler", "route", "path"]
        .into_iter()
        .find_map(|key| fields.get(key).and_then(Value::as_str))
        .map_or(Value::Null, |name| json!(name))
}

fn entry_point_location(fields: &serde_json::Map<String, Value>) -> Value {
    let Some(path) = fields.get("path").and_then(Value::as_str) else {
        return Value::Null;
    };
    fields
        .get("line")
        .and_then(Value::as_u64)
        .map_or_else(|| json!(path), |line| json!(format!("{path}:{line}")))
}

fn is_entry_point_kind(kind: &str) -> bool {
    matches!(
        kind,
        "http-route"
            | "http_route"
            | "rpc-endpoint"
            | "rpc_endpoint"
            | "rpc-handler"
            | "rpc_handler"
            | "websocket"
            | "graphql-resolver"
            | "cli-entrypoint"
            | "cli_entrypoint"
            | "scheduled-job"
            | "background-job"
            | "background_job"
            | "message-consumer"
            | "external-service-client"
            | "external_service_client"
            | "deserialization-point"
            | "deserialization_point"
            | "file-upload-parse-path"
            | "file_upload_parse_path"
    )
}

fn write_entry_points_json(
    target: &Path,
    snapshot: &Value,
    entry_points: &[Value],
) -> Result<PathBuf> {
    let body = json!({
        "target": target.display().to_string(),
        "timestamp": now_ms()?,
        "snapshotTimestamp": snapshot.get("timestamp").cloned().unwrap_or(Value::Null),
        "total": entry_points.len(),
        "entryPoints": entry_points,
    });
    let contents = serde_json::to_vec_pretty(&body).context("serializing entry-points artifact")?;
    crate::workspace::write_workspace_state_file(
        target,
        Path::new(crate::workspace::KUZUSHI_STATE_DIR).join("entry-points.json"),
        &contents,
    )
}

fn entry_points_response(target: &Path, path: &Path, entry_points: &[Value]) -> Value {
    let output = format!(
        "entry-points:extract wrote {} entry point{} under {}\n  Output: {}",
        entry_points.len(),
        if entry_points.len() == 1 { "" } else { "s" },
        target.display(),
        path.display()
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "outputPath": path.display().to_string(),
            "total": entry_points.len(),
            "entryPoints": entry_points,
        }),
    )
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis() as u64)
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, label: impl Into<String>) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, label.into()).emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn extractor_reads_canonical_surfaces_and_preserves_grounding_fields() {
        let snapshot = json!({
            "attackSurfaceMap": {
                "surfaces": [{
                    "id": "AS-route",
                    "kind": "http_route",
                    "path": "src/api.rs",
                    "line": 42,
                    "title": "POST /oauth/callback",
                    "evidence": "router.post",
                    "method": "POST",
                    "route": "/oauth/callback",
                    "boundary": "public_http",
                    "risk": {"score": 80},
                    "metadata": {"handler": "oauth_callback"}
                }]
            }
        });

        let rows = collect_entry_points(&snapshot);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], json!("AS-route"));
        assert_eq!(rows[0]["name"], json!("POST /oauth/callback"));
        assert_eq!(rows[0]["location"], json!("src/api.rs:42"));
        assert_eq!(rows[0]["evidence"], json!("router.post"));
        assert_eq!(rows[0]["metadata"]["handler"], json!("oauth_callback"));
    }

    #[test]
    fn extractor_keeps_legacy_nodes_as_a_compatibility_fallback() {
        let snapshot = json!({
            "attackSurfaceMap": {
                "nodes": [{
                    "kind": "rpc-endpoint",
                    "handler": "legacy_handler",
                    "path": "src/rpc.rs"
                }]
            }
        });

        let rows = collect_entry_points(&snapshot);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], json!("legacy_handler"));
    }

    #[cfg(unix)]
    #[test]
    fn entry_points_writer_rejects_a_symlinked_artifact() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
        fs::write(outside.path(), "outside").unwrap();
        symlink(
            outside.path(),
            workspace.path().join(".kuzushi/entry-points.json"),
        )
        .unwrap();

        let error = write_entry_points_json(workspace.path(), &json!({}), &[]).unwrap_err();

        assert!(error.to_string().contains("symlink"));
        assert_eq!(fs::read_to_string(outside.path()).unwrap(), "outside");
    }
}
