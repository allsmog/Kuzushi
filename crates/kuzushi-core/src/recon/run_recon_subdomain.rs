use super::*;

pub(crate) fn run_recon_subdomain(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:subdomain needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let options = SubdomainInput::from_tool_input(input)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "subdomain",
                format!("recon:subdomain start · domain={}", options.domain),
            )
            .emit();
    }
    let enumerator = ReconSubdomainEnumerator::from_input(&options);
    let subdomains = enumerator.enumerate(cancel)?;
    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;

    let mut hosts = Vec::new();
    for subdomain in &subdomains {
        hosts.push(store.upsert_host(
            &workspace_id,
            subdomain,
            Some(subdomain),
            "alive",
            json!({
                "discoveredBy": "recon:subdomain",
                "discoveredAt": now_isoish(),
                "domain": options.domain,
                "source": options.source.as_str(),
            }),
        )?);
    }
    let note = store.create_note(
        &workspace_id,
        None,
        None,
        "recon:subdomain",
        json!({
            "domain": options.domain,
            "source": options.source.as_str(),
            "count": subdomains.len(),
            "subdomains": subdomains,
        }),
    )?;

    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "subdomain",
                format!(
                    "recon:subdomain complete · {} subdomains",
                    subdomains.len()
                ),
            )
            .emit();
    }
    Ok(ReconReport {
        tool: "recon:subdomain".to_string(),
        target: options.domain,
        hosts,
        services: Vec::new(),
        notes: vec![note],
        persisted: ReconPersisted {
            workspace_id,
            db: workspace.findings_db_path().display().to_string(),
            host_count: store.count_hosts()?,
            service_count: store.count_services()?,
        },
        subdomains,
        fingerprint: BTreeMap::new(),
    })
}
