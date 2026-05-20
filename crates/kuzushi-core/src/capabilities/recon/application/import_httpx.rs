use super::*;

/// Import an httpx JSONL probe dump (`httpx -json -o out.jsonl`) into
/// the recon store as `ReconHost` + `ReconService` rows. Each line
/// carries `host`, `port`, `scheme`, `status_code`, `title`, and
/// `tech[]`. Lines without a host are skipped.
pub(crate) fn run_recon_import_httpx(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:import needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let path = required_path(input, "path", "recon:import httpx needs a `path` field")?;
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;

    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;
    let mut hosts = Vec::new();
    let mut services = Vec::new();
    let mut notes = Vec::new();

    for (lineno, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(trimmed)
            .with_context(|| format!("httpx JSONL line {} is not valid JSON", lineno + 1))?;
        let Some(host) = entry.get("host").and_then(Value::as_str) else {
            continue;
        };
        let port = entry
            .get("port")
            .and_then(Value::as_u64)
            .map(|p| p.min(u16::MAX as u64) as u16)
            .unwrap_or_else(|| default_port_for(&entry));
        let scheme = entry.get("scheme").and_then(Value::as_str).unwrap_or("http");

        let recorded_host = store.upsert_host(
            &workspace_id,
            host,
            Some(host),
            "alive",
            json!({
                "discoveredBy": "recon:import-httpx",
                "discoveredAt": now_isoish(),
            }),
        )?;

        // services.proto is constrained to tcp/udp/icmp/sctp; the URL
        // scheme (http/https) and webserver/tech metadata land in the
        // info JSON instead. The service name prefers `webserver` →
        // first `tech[]` entry → scheme so the operator sees a useful
        // label in the recon view.
        let service_name = service_name_from_entry(&entry, scheme);
        let recorded_service = store.upsert_service(
            &recorded_host.id,
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
        )?;

        let note = store.create_note(
            &workspace_id,
            Some(&recorded_host.id),
            Some(&recorded_service.id),
            "recon:import-httpx",
            json!({
                "url": entry.get("url").cloned().unwrap_or(Value::Null),
                "status_code": entry.get("status_code").cloned().unwrap_or(Value::Null),
                "title": entry.get("title").cloned().unwrap_or(Value::Null),
                "tech": entry.get("tech").cloned().unwrap_or(Value::Null),
            }),
        )?;
        hosts.push(recorded_host);
        services.push(recorded_service);
        notes.push(note);
    }

    Ok(ReconReport {
        tool: "recon:import-httpx".to_string(),
        target: path.display().to_string(),
        hosts,
        services,
        notes,
        persisted: ReconPersisted {
            workspace_id,
            db: workspace.findings_db_path().display().to_string(),
            host_count: store.count_hosts()?,
            service_count: store.count_services()?,
        },
        subdomains: Vec::new(),
        fingerprint: BTreeMap::new(),
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
