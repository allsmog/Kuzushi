use super::*;

pub(crate) fn run_recon_subdomain(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "recon:subdomain",
        ))?;
    let options = SubdomainInput::from_tool_input(input)?;
    emit_subdomain_trace(ctx, "tool", format!("start · domain={}", options.domain));

    let enumerator = ReconSubdomainEnumerator::from_input(&options);
    let subdomains = enumerator.enumerate(cancel)?;
    let persisted = persist_subdomain_results(workspace, &options, &subdomains)?;
    emit_subdomain_trace(
        ctx,
        "done",
        format!("complete · {} subdomains", subdomains.len()),
    );

    Ok(ReconReport {
        tool: "recon:subdomain".to_string(),
        target: options.domain,
        hosts: persisted.hosts,
        services: Vec::new(),
        notes: vec![persisted.note],
        persisted: persisted.summary,
        skipped_out_of_scope: None,
        subdomains,
        fingerprint: BTreeMap::new(),
    })
}

struct PersistedSubdomains {
    hosts: Vec<ReconHost>,
    note: ReconNote,
    summary: ReconPersisted,
}

fn persist_subdomain_results(
    workspace: &crate::workspace::WorkspaceTarget,
    options: &SubdomainInput,
    subdomains: &[String],
) -> Result<PersistedSubdomains> {
    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;
    let hosts = record_subdomain_hosts(&store, &workspace_id, options, subdomains)?;
    let note = record_subdomain_note(&store, &workspace_id, options, subdomains)?;
    let summary = recon_persisted_summary(&store, workspace, workspace_id)?;
    Ok(PersistedSubdomains {
        hosts,
        note,
        summary,
    })
}

fn record_subdomain_hosts(
    store: &ReconWorkspaceStore,
    workspace_id: &str,
    options: &SubdomainInput,
    subdomains: &[String],
) -> Result<Vec<ReconHost>> {
    let mut hosts = Vec::new();
    for subdomain in subdomains {
        hosts.push(store.upsert_host(
            workspace_id,
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
    Ok(hosts)
}

fn record_subdomain_note(
    store: &ReconWorkspaceStore,
    workspace_id: &str,
    options: &SubdomainInput,
    subdomains: &[String],
) -> Result<ReconNote> {
    store.create_note(
        workspace_id,
        None,
        None,
        "recon:subdomain",
        json!({
            "domain": &options.domain,
            "source": options.source.as_str(),
            "count": subdomains.len(),
            "subdomains": subdomains,
        }),
    )
}

fn recon_persisted_summary(
    store: &ReconWorkspaceStore,
    workspace: &crate::workspace::WorkspaceTarget,
    workspace_id: String,
) -> Result<ReconPersisted> {
    Ok(ReconPersisted {
        workspace_id,
        db: workspace.findings_db_path().display().to_string(),
        host_count: store.count_hosts()?,
        service_count: store.count_services()?,
    })
}

fn emit_subdomain_trace(ctx: &ToolExecutionContext<'_>, kind: &'static str, message: String) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(kind, "subdomain", format!("recon:subdomain {message}"))
            .emit();
    }
}
