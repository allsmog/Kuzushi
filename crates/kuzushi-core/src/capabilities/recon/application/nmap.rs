use super::*;

pub(crate) fn run_recon_nmap(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let run = prepare_recon_nmap(input, ctx)?;
    let parsed = scan_recon_nmap(&run.options, cancel)?;
    let persisted = persist_recon_nmap_result(&run, parsed)?;
    emit_recon_nmap_done(ctx, persisted.hosts.len(), persisted.services.len());
    Ok(recon_nmap_report(&run, persisted))
}

struct ReconNmapRun<'a> {
    workspace: &'a crate::workspace::WorkspaceTarget,
    options: NmapInput,
}

fn prepare_recon_nmap<'a>(
    input: &Value,
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<ReconNmapRun<'a>> {
    let workspace = require_recon_nmap_workspace(ctx)?;
    let options = NmapInput::from_tool_input(input)?;
    emit_recon_nmap_start(ctx, &options);
    Ok(ReconNmapRun { workspace, options })
}

fn require_recon_nmap_workspace<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a crate::workspace::WorkspaceTarget> {
    ctx.workspace
        .context(crate::workspace::active_workspace_required_message("recon:nmap"))
}

fn scan_recon_nmap(options: &NmapInput, cancel: &ScanCancellation) -> Result<NmapParseResult> {
    ReconNmapScanner::from_input(options).scan(cancel)
}

struct PersistedReconNmap {
    workspace_id: String,
    hosts: Vec<ReconHost>,
    services: Vec<ReconService>,
    note: ReconNote,
    host_count: usize,
    service_count: usize,
}

fn persist_recon_nmap_result(
    run: &ReconNmapRun<'_>,
    parsed: NmapParseResult,
) -> Result<PersistedReconNmap> {
    let mut store = ReconWorkspaceStore::open(run.workspace)?;
    let workspace_id = store.ensure_default_workspace(run.workspace.root())?;
    let (hosts, services) =
        persist_recon_nmap_hosts(&mut store, &workspace_id, &run.options, parsed)?;
    let note = create_recon_nmap_note(&mut store, &workspace_id, &run.options, &hosts, &services)?;
    Ok(PersistedReconNmap {
        workspace_id,
        hosts,
        services,
        note,
        host_count: store.count_hosts()?,
        service_count: store.count_services()?,
    })
}

fn persist_recon_nmap_hosts(
    store: &mut ReconWorkspaceStore,
    workspace_id: &str,
    options: &NmapInput,
    parsed: NmapParseResult,
) -> Result<(Vec<ReconHost>, Vec<ReconService>)> {
    let mut hosts = Vec::new();
    let mut services = Vec::new();
    for discovered_host in parsed.hosts {
        let (host, host_services) =
            persist_recon_nmap_host(store, workspace_id, options, discovered_host)?;
        services.extend(host_services);
        hosts.push(host);
    }
    Ok((hosts, services))
}

fn persist_recon_nmap_host(
    store: &mut ReconWorkspaceStore,
    workspace_id: &str,
    options: &NmapInput,
    discovered_host: NmapHost,
) -> Result<(ReconHost, Vec<ReconService>)> {
    let host = store.upsert_host(
        workspace_id,
        &discovered_host.address,
        discovered_host.hostname.as_deref(),
        "alive",
        nmap_host_metadata(options),
    )?;
    let services = persist_recon_nmap_services(store, &host.id, options, discovered_host.services)?;
    Ok((host, services))
}

fn persist_recon_nmap_services(
    store: &mut ReconWorkspaceStore,
    host_id: &str,
    options: &NmapInput,
    discovered_services: Vec<NmapService>,
) -> Result<Vec<ReconService>> {
    let mut services = Vec::new();
    for discovered_service in discovered_services {
        services.push(persist_recon_nmap_service(
            store,
            host_id,
            options,
            discovered_service,
        )?);
    }
    Ok(services)
}

fn persist_recon_nmap_service(
    store: &mut ReconWorkspaceStore,
    host_id: &str,
    options: &NmapInput,
    discovered_service: NmapService,
) -> Result<ReconService> {
    store.upsert_service(
        host_id,
        discovered_service.port,
        &discovered_service.proto,
        discovered_service.name.as_deref(),
        discovered_service.banner.as_deref(),
        &discovered_service.state,
        nmap_service_metadata(options),
    )
}

fn create_recon_nmap_note(
    store: &mut ReconWorkspaceStore,
    workspace_id: &str,
    options: &NmapInput,
    hosts: &[ReconHost],
    services: &[ReconService],
) -> Result<ReconNote> {
    store.create_note(
        workspace_id,
        None,
        None,
        "recon:nmap",
        nmap_summary_payload(options, hosts.len(), services.len()),
    )
}

fn nmap_host_metadata(options: &NmapInput) -> Value {
    json!({
        "discoveredBy": "recon:nmap",
        "discoveredAt": now_isoish(),
        "target": options.target,
        "ports": options.ports,
    })
}

fn nmap_service_metadata(options: &NmapInput) -> Value {
    json!({
        "discoveredBy": "recon:nmap",
        "target": options.target,
        "ports": options.ports,
    })
}

fn nmap_summary_payload(options: &NmapInput, host_count: usize, service_count: usize) -> Value {
    json!({
        "target": options.target,
        "ports": options.ports,
        "hosts": host_count,
        "services": service_count,
    })
}

fn emit_recon_nmap_start(ctx: &ToolExecutionContext<'_>, options: &NmapInput) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "nmap",
                format!("recon:nmap start · target={}", options.target),
            )
            .emit();
    }
}

fn emit_recon_nmap_done(ctx: &ToolExecutionContext<'_>, host_count: usize, service_count: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "nmap",
                format!("recon:nmap complete · {host_count} hosts · {service_count} services"),
            )
            .emit();
    }
}

fn recon_nmap_report(run: &ReconNmapRun<'_>, persisted: PersistedReconNmap) -> ReconReport {
    ReconReport {
        tool: "recon:nmap".to_string(),
        target: run.options.target.clone(),
        hosts: persisted.hosts,
        services: persisted.services,
        notes: vec![persisted.note],
        persisted: ReconPersisted {
            workspace_id: persisted.workspace_id,
            db: run.workspace.findings_db_path().display().to_string(),
            host_count: persisted.host_count,
            service_count: persisted.service_count,
        },
        subdomains: Vec::new(),
        fingerprint: BTreeMap::new(),
    }
}
