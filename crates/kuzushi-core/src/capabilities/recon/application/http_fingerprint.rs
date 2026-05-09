use super::*;

pub(crate) fn run_recon_http_fingerprint(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:http-fingerprint needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let options = HttpFingerprintInput::from_tool_input(input)?;
    let fingerprinter = ReconHttpFingerprinter::from_input(&options);
    let fingerprint = fingerprinter.fingerprint(cancel)?;
    let endpoint = split_host_port(&options.target);
    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;
    let host = store.upsert_host(
        &workspace_id,
        &endpoint.host,
        Some(&endpoint.host),
        "alive",
        json!({
            "discoveredBy": "recon:http-fingerprint",
            "discoveredAt": now_isoish(),
        }),
    )?;
    let service = store.upsert_service(
        &host.id,
        endpoint.port,
        "tcp",
        Some(if endpoint.port == 443 {
            "https"
        } else {
            "http"
        }),
        fingerprint.server.as_deref(),
        "open",
        json!({
            "discoveredBy": "recon:http-fingerprint",
            "status": fingerprint.status,
            "headers": fingerprint.headers,
            "technologies": fingerprint.technologies,
            "title": fingerprint.title,
        }),
    )?;
    let mut fingerprint_data = BTreeMap::new();
    fingerprint_data.insert("status".to_string(), json!(fingerprint.status));
    fingerprint_data.insert("headers".to_string(), json!(fingerprint.headers));
    fingerprint_data.insert("technologies".to_string(), json!(fingerprint.technologies));
    if let Some(server) = &fingerprint.server {
        fingerprint_data.insert("server".to_string(), json!(server));
    }
    if let Some(title) = &fingerprint.title {
        fingerprint_data.insert("title".to_string(), json!(title));
    }
    let note = store.create_note(
        &workspace_id,
        Some(&host.id),
        Some(&service.id),
        "recon:http-fingerprint",
        json!({
            "target": options.target,
            "status": fingerprint.status,
            "server": fingerprint.server,
            "title": fingerprint.title,
            "technologies": fingerprint.technologies,
        }),
    )?;

    Ok(ReconReport {
        tool: "recon:http-fingerprint".to_string(),
        target: options.target,
        hosts: vec![host],
        services: vec![service],
        notes: vec![note],
        persisted: ReconPersisted {
            workspace_id,
            db: workspace.findings_db_path().display().to_string(),
            host_count: store.count_hosts()?,
            service_count: store.count_services()?,
        },
        subdomains: Vec::new(),
        fingerprint: fingerprint_data,
    })
}
