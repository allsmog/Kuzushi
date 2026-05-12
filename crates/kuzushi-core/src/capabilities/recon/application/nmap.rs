use super::*;

pub(crate) fn run_recon_nmap(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:nmap needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let options = NmapInput::from_tool_input(input)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "nmap",
                format!("recon:nmap start · target={}", options.target),
            )
            .emit();
    }
    let scan = ReconNmapScanner::from_input(&options);
    let parsed = scan.scan(cancel)?;
    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;

    let mut hosts = Vec::new();
    let mut services = Vec::new();
    for discovered_host in parsed.hosts {
        let host = store.upsert_host(
            &workspace_id,
            &discovered_host.address,
            discovered_host.hostname.as_deref(),
            "alive",
            json!({
                "discoveredBy": "recon:nmap",
                "discoveredAt": now_isoish(),
                "target": options.target,
                "ports": options.ports,
            }),
        )?;
        for discovered_service in discovered_host.services {
            let service = store.upsert_service(
                &host.id,
                discovered_service.port,
                &discovered_service.proto,
                discovered_service.name.as_deref(),
                discovered_service.banner.as_deref(),
                &discovered_service.state,
                json!({
                    "discoveredBy": "recon:nmap",
                    "target": options.target,
                    "ports": options.ports,
                }),
            )?;
            services.push(service);
        }
        hosts.push(host);
    }

    let note = store.create_note(
        &workspace_id,
        None,
        None,
        "recon:nmap",
        json!({
            "target": options.target,
            "ports": options.ports,
            "hosts": hosts.len(),
            "services": services.len(),
        }),
    )?;

    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "nmap",
                format!(
                    "recon:nmap complete · {} hosts · {} services",
                    hosts.len(),
                    services.len()
                ),
            )
            .emit();
    }
    Ok(ReconReport {
        tool: "recon:nmap".to_string(),
        target: options.target,
        hosts,
        services,
        notes: vec![note],
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
