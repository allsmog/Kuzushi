use super::*;

const TOOL: &str = "recon:import-httpx";

/// Import an httpx JSONL probe dump (`httpx -json -o out.jsonl`) into
/// the recon store as `ReconHost` + `ReconService` rows. Out-of-scope
/// hosts (per `.kuzushi/scope.toml`) and parsed rows without a usable host
/// are accounted separately in the import summary.
pub(crate) fn run_recon_import_httpx(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message("recon:import"))?;
    let (path, body) = read_jsonl_path(input, "recon:import httpx needs a `path` field")?;
    let mut context = ReconImportContext::open(workspace)?;
    let record_count = body.lines().filter(|line| !line.trim().is_empty()).count();
    for (lineno, line) in body.lines().enumerate() {
        ingest_httpx_line(&mut context, line, lineno)?;
    }
    append_httpx_import_summary(&mut context, &path, record_count)?;
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
    let Some(host) = httpx_host(&entry) else {
        context.skip_unusable_host();
        return Ok(());
    };
    if !context.admit_host(&host) {
        return Ok(());
    }
    persist_httpx_entry(context, &host, &entry)
}

fn httpx_host(entry: &Value) -> Option<String> {
    string_field(entry, "host")
        .or_else(|| string_field(entry, "input"))
        .or_else(|| {
            string_field(entry, "url").and_then(|url| {
                url::Url::parse(&url)
                    .ok()
                    .and_then(|parsed| parsed.host_str().map(str::to_string))
            })
        })
}

fn string_field(entry: &Value, key: &str) -> Option<String> {
    entry
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
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
    let scheme = httpx_scheme(entry);
    let service_name = service_name_from_entry(entry, &scheme);
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
            "status_code": httpx_status_code(entry),
            "tech": entry.get("tech").cloned().unwrap_or(Value::Null),
            "raw": entry.clone(),
        }),
    )
}

fn httpx_port(entry: &Value) -> u16 {
    entry
        .get("port")
        .and_then(Value::as_u64)
        .or_else(|| {
            entry
                .get("port")
                .and_then(Value::as_str)
                .and_then(|port| port.parse().ok())
        })
        // An out-of-range port in hostile capture data is dropped, not
        // clamped: clamping would mint a real-looking port 65535 record.
        .and_then(|p| u16::try_from(p).ok())
        .or_else(|| {
            string_field(entry, "url").and_then(|url| {
                url::Url::parse(&url)
                    .ok()
                    .and_then(|parsed| parsed.port_or_known_default())
            })
        })
        .unwrap_or_else(|| default_port_for(entry))
}

fn httpx_note_payload(entry: &Value) -> Value {
    json!({
        "url": entry.get("url").cloned().unwrap_or(Value::Null),
        "status_code": httpx_status_code(entry),
        "title": entry.get("title").cloned().unwrap_or(Value::Null),
        "tech": entry.get("tech").cloned().unwrap_or(Value::Null),
    })
}

fn default_port_for(entry: &Value) -> u16 {
    if httpx_scheme(entry) == "https" { 443 } else { 80 }
}

fn httpx_scheme(entry: &Value) -> String {
    string_field(entry, "scheme")
        .or_else(|| {
            string_field(entry, "url")
                .and_then(|url| url::Url::parse(&url).ok().map(|parsed| parsed.scheme().to_string()))
        })
        .unwrap_or_else(|| "http".to_string())
}

fn httpx_status_code(entry: &Value) -> Value {
    entry
        .get("status_code")
        .or_else(|| entry.get("status-code"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn append_httpx_import_summary(
    context: &mut ReconImportContext<'_>,
    path: &std::path::Path,
    record_count: usize,
) -> Result<()> {
    let imported = context.hosts.len();
    let skipped = context.skipped_out_of_scope;
    let skipped_unusable = context.skipped_unusable;
    context.notes.push(context.store.create_note(
        &context.workspace_id,
        None,
        None,
        TOOL,
        json!({
            "path": path.display().to_string(),
            "records": record_count,
            "imported": imported,
            "skippedOutOfScope": skipped,
            "skippedUnusable": skipped_unusable,
            "ignored": skipped_unusable,
        }),
    )?);
    Ok(())
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

#[cfg(test)]
mod port_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn out_of_range_ports_are_dropped_not_clamped() {
        // Clamping 70000 would mint a real-looking port-65535 service.
        assert_eq!(httpx_port(&json!({ "port": 70000, "url": "https://a.test" })), 443);
        assert_eq!(httpx_port(&json!({ "port": 8443 })), 8443);
        assert_eq!(httpx_port(&json!({ "port": "70000", "url": "http://a.test" })), 80);
    }
}

