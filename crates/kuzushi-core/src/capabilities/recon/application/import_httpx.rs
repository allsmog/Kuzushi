use super::*;

const TOOL: &str = "recon:import-httpx";

/// Import an httpx JSONL probe dump (`httpx -json -o out.jsonl`) into
/// the recon store as `ReconHost` + `ReconService` rows. Out-of-scope
/// hosts (per `.kuzushi/scope.toml`) are skipped with a counter.
pub(crate) fn run_recon_import_httpx(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message("recon:import"))?;
    let (path, body) = read_jsonl_path(input, "recon:import httpx needs a `path` field")?;
    let mut context = ReconImportContext::open(workspace)?;
    for (lineno, line) in body.lines().enumerate() {
        ingest_httpx_line(&mut context, line, lineno)?;
    }
    context.into_report(TOOL, path.display().to_string())
}

fn ingest_httpx_line(
    context: &mut ReconImportContext<'_>,
    line: &str,
    lineno: usize,
) -> Result<()> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let entry: Value = serde_json::from_str(trimmed)
        .with_context(|| format!("httpx JSONL line {} is not valid JSON", lineno + 1))?;
    let Some(host) = entry.get("host").and_then(Value::as_str) else {
        return Ok(());
    };
    if !context.admit_host(host) {
        return Ok(());
    }
    persist_httpx_entry(context, host, &entry)
}

fn persist_httpx_entry(
    context: &mut ReconImportContext<'_>,
    host: &str,
    entry: &Value,
) -> Result<()> {
    let recorded_host = context.store.upsert_host(
        &context.workspace_id,
        host,
        Some(host),
        "alive",
        json!({
            "discoveredBy": TOOL,
            "discoveredAt": now_isoish(),
        }),
    )?;
    let recorded_service = upsert_httpx_service(&context.store, &recorded_host.id, entry)?;
    let note = context.store.create_note(
        &context.workspace_id,
        Some(&recorded_host.id),
        Some(&recorded_service.id),
        TOOL,
        httpx_note_payload(entry),
    )?;
    context.hosts.push(recorded_host);
    context.services.push(recorded_service);
    context.notes.push(note);
    Ok(())
}

fn upsert_httpx_service(
    store: &ReconWorkspaceStore,
    host_id: &str,
    entry: &Value,
) -> Result<ReconService> {
    let port = httpx_port(entry);
    let scheme = entry.get("scheme").and_then(Value::as_str).unwrap_or("http");
    let service_name = service_name_from_entry(entry, scheme);
    store.upsert_service(
        host_id,
        port,
        "tcp",
        Some(&service_name),
        entry.get("title").and_then(Value::as_str),
        "open",
        json!({
            "scheme": scheme,
            "title": entry.get("title").cloned().unwrap_or(Value::Null),
            "status_code": entry.get("status_code").cloned().unwrap_or(Value::Null),
            "tech": entry.get("tech").cloned().unwrap_or(Value::Null),
            "raw": entry.clone(),
        }),
    )
}

fn httpx_port(entry: &Value) -> u16 {
    entry
        .get("port")
        .and_then(Value::as_u64)
        .map(|p| p.min(u16::MAX as u64) as u16)
        .unwrap_or_else(|| default_port_for(entry))
}

fn httpx_note_payload(entry: &Value) -> Value {
    json!({
        "url": entry.get("url").cloned().unwrap_or(Value::Null),
        "status_code": entry.get("status_code").cloned().unwrap_or(Value::Null),
        "title": entry.get("title").cloned().unwrap_or(Value::Null),
        "tech": entry.get("tech").cloned().unwrap_or(Value::Null),
    })
}

fn default_port_for(entry: &Value) -> u16 {
    match entry.get("scheme").and_then(Value::as_str) {
        Some("https") => 443,
        _ => 80,
    }
}

fn service_name_from_entry(entry: &Value, scheme: &str) -> String {
    if let Some(webserver) = entry.get("webserver").and_then(Value::as_str) {
        if !webserver.is_empty() {
            return webserver.to_string();
        }
    }
    if let Some(tech) = entry
        .get("tech")
        .and_then(Value::as_array)
        .and_then(|tech| tech.first())
        .and_then(Value::as_str)
    {
        return tech.to_string();
    }
    scheme.to_string()
}
