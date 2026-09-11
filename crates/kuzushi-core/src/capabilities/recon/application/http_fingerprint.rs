use super::*;
use crate::capabilities::recon::domain::{HttpFingerprint, ReconHost, ReconNote, ReconService};
use std::path::Path;

pub(crate) fn run_recon_http_fingerprint(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        crate::workspace::active_workspace_required_message("recon:http-fingerprint"),
    )?;
    let options = HttpFingerprintInput::from_tool_input(input)?;
    emit_http_fingerprint_start(ctx, &options);
    let fingerprinter = ReconHttpFingerprinter::from_input(&options);
    let fingerprint = fingerprinter.fingerprint(cancel)?;
    let endpoint = split_host_port(&options.target);
    let mut store = ReconWorkspaceStore::open(workspace)?;
    let persisted_entities = persist_http_fingerprint(
        &mut store,
        workspace.root(),
        &endpoint.host,
        endpoint.port,
        &fingerprint,
        &options,
    )?;
    emit_http_fingerprint_done(ctx, &fingerprint);
    http_fingerprint_report(
        workspace,
        &mut store,
        options,
        fingerprint,
        persisted_entities,
    )
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

fn persist_http_fingerprint(
    store: &mut ReconWorkspaceStore,
    workspace_root: &Path,
    host_name: &str,
    port: u16,
    fingerprint: &HttpFingerprint,
    options: &HttpFingerprintInput,
) -> Result<HttpFingerprintPersistence> {
    let workspace_id = store.ensure_default_workspace(workspace_root)?;
    let host = store.upsert_host(
        &workspace_id,
        host_name,
        Some(host_name),
        "alive",
        json!({
            "discoveredBy": "recon:http-fingerprint",
            "discoveredAt": now_isoish(),
        }),
    )?;
    let service = store.upsert_service(
        &host.id,
        port,
        "tcp",
        Some(http_scheme_for_port(port)),
        fingerprint.server.as_deref(),
        "open",
        http_service_metadata(fingerprint),
    )?;
    let note = store.create_note(
        &workspace_id,
        Some(&host.id),
        Some(&service.id),
        "recon:http-fingerprint",
        http_fingerprint_note_payload(options, fingerprint),
    )?;
    Ok(HttpFingerprintPersistence {
        workspace_id,
        host,
        service,
        note,
    })
}

fn http_scheme_for_port(port: u16) -> &'static str {
    if port == 443 {
        "https"
    } else {
        "http"
    }
}

fn http_service_metadata(fingerprint: &HttpFingerprint) -> Value {
    json!({
        "discoveredBy": "recon:http-fingerprint",
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

fn http_fingerprint_note_payload(
    options: &HttpFingerprintInput,
    fingerprint: &HttpFingerprint,
) -> Value {
    json!({
        "target": &options.target,
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
    fingerprint: HttpFingerprint,
    persisted: HttpFingerprintPersistence,
) -> Result<ReconReport> {
    let fingerprint_data = http_fingerprint_data(&fingerprint);
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
    })
}
