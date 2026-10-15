use super::*;
use crate::capabilities::recon::application::http_fingerprint_walk::{
    walk_http_fingerprint, FingerprintWalk,
};
use crate::capabilities::recon::domain::{
    endpoint_from_url, http_target_url, Endpoint, HttpFingerprint, ReconHost, ReconNote,
    ReconService,
};
use std::path::Path;

pub(crate) fn run_recon_http_fingerprint(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "recon:http-fingerprint",
        ))?;
    let options = HttpFingerprintInput::from_tool_input(input)?;
    emit_http_fingerprint_start(ctx, &options);
    let scope =
        crate::workspace::load_program_scope(workspace).context("Could not load scope.toml")?;
    let walk = walk_http_fingerprint(
        &ReconHttpFingerprinter::from_input(&options),
        http_target_url(&options.target)?,
        scope.as_ref(),
        cancel,
    )?;
    require_recon_active(cancel)?;
    let endpoint = endpoint_from_url(walk.answered())?;
    let mut store = ReconWorkspaceStore::open(workspace)?;
    let persisted_entities =
        persist_http_fingerprint(&mut store, workspace.root(), &endpoint, &walk, &options)?;
    emit_http_fingerprint_done(ctx, &walk.fingerprint);
    http_fingerprint_report(workspace, &mut store, options, walk, persisted_entities)
}

fn emit_http_fingerprint_start(ctx: &ToolExecutionContext<'_>, options: &HttpFingerprintInput) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "http-fingerprint",
                format!("recon:http-fingerprint start · target={}", options.target),
            )
            .emit();
    }
}

struct HttpFingerprintPersistence {
    workspace_id: String,
    host: ReconHost,
    service: ReconService,
    note: ReconNote,
}

/// Record the host, service, and note against the endpoint that answered
/// rather than against the target that was asked for.
fn persist_http_fingerprint(
    store: &mut ReconWorkspaceStore,
    workspace_root: &Path,
    endpoint: &Endpoint,
    walk: &FingerprintWalk,
    options: &HttpFingerprintInput,
) -> Result<HttpFingerprintPersistence> {
    let workspace_id = store.ensure_default_workspace(workspace_root)?;
    let host = upsert_fingerprinted_host(store, &workspace_id, &endpoint.host)?;
    let service = upsert_fingerprinted_service(store, &host.id, endpoint, walk)?;
    let note = store.create_note(
        &workspace_id,
        Some(&host.id),
        Some(&service.id),
        "recon:http-fingerprint",
        http_fingerprint_note_payload(options, walk),
    )?;
    Ok(HttpFingerprintPersistence {
        workspace_id,
        host,
        service,
        note,
    })
}

fn upsert_fingerprinted_host(
    store: &mut ReconWorkspaceStore,
    workspace_id: &str,
    host: &str,
) -> Result<ReconHost> {
    store.upsert_host(
        workspace_id,
        host,
        Some(host),
        "alive",
        json!({
            "discoveredBy": "recon:http-fingerprint",
            "discoveredAt": now_isoish(),
        }),
    )
}

/// The service keeps the scheme the fetch actually spoke rather than a guess
/// from the port number, so a cleartext service on 443 is not filed as `https`.
fn upsert_fingerprinted_service(
    store: &mut ReconWorkspaceStore,
    host_id: &str,
    endpoint: &Endpoint,
    walk: &FingerprintWalk,
) -> Result<ReconService> {
    store.upsert_service(
        host_id,
        endpoint.port,
        "tcp",
        Some(&endpoint.scheme),
        walk.fingerprint.server.as_deref(),
        "open",
        http_service_metadata(walk),
    )
}

fn http_service_metadata(walk: &FingerprintWalk) -> Value {
    let fingerprint = &walk.fingerprint;
    json!({
        "discoveredBy": "recon:http-fingerprint",
        "url": walk.answered().to_string(),
        "status": fingerprint.status,
        "headers": &fingerprint.headers,
        "technologies": &fingerprint.technologies,
        "title": &fingerprint.title,
    })
}

fn http_fingerprint_data(fingerprint: &HttpFingerprint) -> BTreeMap<String, Value> {
    let mut fingerprint_data = BTreeMap::new();
    fingerprint_data.insert("status".to_string(), json!(fingerprint.status));
    fingerprint_data.insert("headers".to_string(), json!(&fingerprint.headers));
    fingerprint_data.insert("technologies".to_string(), json!(&fingerprint.technologies));
    if let Some(server) = &fingerprint.server {
        fingerprint_data.insert("server".to_string(), json!(server));
    }
    if let Some(title) = &fingerprint.title {
        fingerprint_data.insert("title".to_string(), json!(title));
    }
    fingerprint_data
}

/// The note keeps the target as it was requested and names the URL that
/// answered it separately, so a redirected run leaves both facts on the record.
fn http_fingerprint_note_payload(options: &HttpFingerprintInput, walk: &FingerprintWalk) -> Value {
    let fingerprint = &walk.fingerprint;
    json!({
        "target": &options.target,
        "fingerprintedUrl": walk.answered().to_string(),
        "redirects": walk.redirects(),
        "status": fingerprint.status,
        "server": &fingerprint.server,
        "title": &fingerprint.title,
        "technologies": &fingerprint.technologies,
    })
}

fn emit_http_fingerprint_done(ctx: &ToolExecutionContext<'_>, fingerprint: &HttpFingerprint) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "http-fingerprint",
                format!(
                    "recon:http-fingerprint complete · status={}",
                    fingerprint
                        .status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".to_string())
                ),
            )
            .emit();
    }
}

fn http_fingerprint_report(
    workspace: &crate::workspace::WorkspaceTarget,
    store: &mut ReconWorkspaceStore,
    options: HttpFingerprintInput,
    walk: FingerprintWalk,
    persisted: HttpFingerprintPersistence,
) -> Result<ReconReport> {
    let fingerprint_data = http_fingerprint_data(&walk.fingerprint);
    let redirects = walk.redirects();
    Ok(ReconReport {
        tool: "recon:http-fingerprint".to_string(),
        target: options.target,
        hosts: vec![persisted.host],
        services: vec![persisted.service],
        notes: vec![persisted.note],
        persisted: ReconPersisted {
            workspace_id: persisted.workspace_id,
            db: workspace.findings_db_path().display().to_string(),
            host_count: store.count_hosts()?,
            service_count: store.count_services()?,
        },
        skipped_out_of_scope: None,
        subdomains: Vec::new(),
        fingerprint: fingerprint_data,
        redirects,
    })
}
