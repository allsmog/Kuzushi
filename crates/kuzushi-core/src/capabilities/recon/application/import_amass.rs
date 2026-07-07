use super::*;

const TOOL: &str = "recon:import-amass";

/// Import an Amass JSONL recon dump (`amass enum -json out.jsonl`) into
/// the recon store as `ReconHost` rows. Out-of-scope hosts (per
/// `.kuzushi/scope.toml`) are skipped silently with a counter.
pub(crate) fn run_recon_import_amass(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message("recon:import"))?;
    let (path, body) = read_jsonl_path(input, "recon:import amass needs a `path` field")?;
    let mut context = ReconImportContext::open(workspace)?;
    for (lineno, line) in body.lines().enumerate() {
        ingest_amass_line(&mut context, line, lineno)?;
    }
    let host_count = context.hosts.len();
    let skipped = context.skipped_out_of_scope;
    context.notes.push(context.store.create_note(
        &context.workspace_id,
        None,
        None,
        TOOL,
        json!({
            "path": path.display().to_string(),
            "count": host_count,
            "skippedOutOfScope": skipped,
        }),
    )?);
    context.into_report(TOOL, path.display().to_string())
}

fn ingest_amass_line(
    context: &mut ReconImportContext<'_>,
    line: &str,
    lineno: usize,
) -> Result<()> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let entry: Value = serde_json::from_str(trimmed)
        .with_context(|| format!("amass JSONL line {} is not valid JSON", lineno + 1))?;
    let Some(name) = entry.get("name").and_then(Value::as_str) else {
        return Ok(());
    };
    if !context.admit_host(name) {
        return Ok(());
    }
    let host = context.store.upsert_host(
        &context.workspace_id,
        name,
        Some(name),
        "alive",
        amass_host_metadata(&entry),
    )?;
    context.hosts.push(host);
    Ok(())
}

fn amass_host_metadata(entry: &Value) -> Value {
    json!({
        "discoveredBy": TOOL,
        "discoveredAt": now_isoish(),
        "domain": entry.get("domain").and_then(Value::as_str),
        "sources": entry.get("sources").cloned().unwrap_or(Value::Null),
        "addresses": entry.get("addresses").cloned().unwrap_or(Value::Null),
        "raw": entry.clone(),
    })
}
