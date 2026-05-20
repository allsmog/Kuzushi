use super::*;

/// Import an Amass JSONL recon dump (`amass enum -json out.jsonl`) into
/// the recon store as `ReconHost` rows. Each line carries a `name`,
/// optional `addresses[].ip`, and one or more `sources[]`. Lines without
/// a name are skipped. Returns a [`ReconReport`] tagged
/// `tool = "recon:import-amass"`.
pub(crate) fn run_recon_import_amass(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:import needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let path = required_path(input, "path", "recon:import amass needs a `path` field")?;
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;

    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;
    let mut hosts = Vec::new();

    for (lineno, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(trimmed)
            .with_context(|| format!("amass JSONL line {} is not valid JSON", lineno + 1))?;
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let metadata = json!({
            "discoveredBy": "recon:import-amass",
            "discoveredAt": now_isoish(),
            "domain": entry.get("domain").and_then(Value::as_str),
            "sources": entry.get("sources").cloned().unwrap_or(Value::Null),
            "addresses": entry.get("addresses").cloned().unwrap_or(Value::Null),
            "raw": entry.clone(),
        });
        let host = store.upsert_host(&workspace_id, name, Some(name), "alive", metadata)?;
        hosts.push(host);
    }

    let count = hosts.len();
    let note = store.create_note(
        &workspace_id,
        None,
        None,
        "recon:import-amass",
        json!({
            "path": path.display().to_string(),
            "count": count,
        }),
    )?;

    Ok(ReconReport {
        tool: "recon:import-amass".to_string(),
        target: path.display().to_string(),
        hosts,
        services: Vec::new(),
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
