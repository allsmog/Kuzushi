use super::*;

/// Import a nuclei JSONL findings dump
/// (`nuclei -jsonl -o out.jsonl`) into the recon store as `ReconNote`
/// rows. One note per template hit, tagged with `severity` for later
/// filtering in the recon view. Findings table is unaffected — nuclei
/// outputs are recorded as recon intelligence, not Kuzushi findings.
pub(crate) fn run_recon_import_nuclei(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:import needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let path = required_path(input, "path", "recon:import nuclei needs a `path` field")?;
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;

    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;
    let mut notes = Vec::new();

    for (lineno, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(trimmed)
            .with_context(|| format!("nuclei JSONL line {} is not valid JSON", lineno + 1))?;
        let template = entry
            .get("template-id")
            .or_else(|| entry.get("templateID"))
            .and_then(Value::as_str)
            .unwrap_or("nuclei");
        let severity = entry
            .pointer("/info/severity")
            .and_then(Value::as_str)
            .unwrap_or("info");
        let host_value = entry
            .get("host")
            .or_else(|| entry.get("matched-at"))
            .and_then(Value::as_str);
        let host_id = match host_value {
            Some(host) => {
                let recorded = store.upsert_host(
                    &workspace_id,
                    host,
                    Some(host),
                    "alive",
                    json!({
                        "discoveredBy": "recon:import-nuclei",
                        "discoveredAt": now_isoish(),
                    }),
                )?;
                Some(recorded.id)
            }
            None => None,
        };
        let note = store.create_note(
            &workspace_id,
            host_id.as_deref(),
            None,
            &format!("recon:import-nuclei:{template}"),
            json!({
                "template": template,
                "severity": severity,
                "matched_at": entry.get("matched-at").cloned().unwrap_or(Value::Null),
                "info": entry.get("info").cloned().unwrap_or(Value::Null),
                "raw": entry.clone(),
            }),
        )?;
        notes.push(note);
    }

    Ok(ReconReport {
        tool: "recon:import-nuclei".to_string(),
        target: path.display().to_string(),
        hosts: Vec::new(),
        services: Vec::new(),
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
