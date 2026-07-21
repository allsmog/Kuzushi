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
    surface
        .get("nodes")
        .and_then(Value::as_array)
        .map(|nodes| nodes.iter().filter_map(normalize_entry_point).collect())
        .unwrap_or_default()
}

fn normalize_entry_point(node: &Value) -> Option<Value> {
    let kind = node.get("kind").and_then(Value::as_str)?;
    if !is_entry_point_kind(kind) {
        return None;
    }
    Some(json!({
        "kind": kind,
        "method": node.get("method").cloned().unwrap_or(Value::Null),
        "path": node.get("path").cloned().unwrap_or(Value::Null),
        "handler": node.get("handler").cloned().unwrap_or(Value::Null),
        "framework": node.get("framework").cloned().unwrap_or(Value::Null),
        "language": node.get("language").cloned().unwrap_or(Value::Null),
        "location": node.get("location").cloned().unwrap_or(Value::Null),
    }))
}

fn is_entry_point_kind(kind: &str) -> bool {
    matches!(
        kind,
        "http-route"
            | "http_route"
            | "rpc-endpoint"
            | "rpc_endpoint"
            | "websocket"
            | "graphql-resolver"
            | "cli-entrypoint"
            | "cli_entrypoint"
            | "scheduled-job"
            | "background-job"
            | "message-consumer"
            | "external-service-client"
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
    use std::fs;
    use super::*;

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
