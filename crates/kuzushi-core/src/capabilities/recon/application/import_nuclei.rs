use super::*;

const TOOL_PREFIX: &str = "recon:import-nuclei";

/// Import a nuclei JSONL findings dump (`nuclei -jsonl -o out.jsonl`)
/// into the recon store as `ReconNote` rows. One note per template hit,
/// tagged with `severity` for later filtering. Hosts `.kuzushi/scope.toml`
/// puts out of scope are skipped, and the count is disclosed in the report
/// and its output line.
pub(crate) fn run_recon_import_nuclei(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message("recon:import"))?;
    let (path, body) = read_jsonl_path(input, "recon:import nuclei needs a `path` field")?;
    let mut context = ReconImportContext::open(workspace)?;
    for (lineno, line) in body.lines().enumerate() {
        ingest_nuclei_line(&mut context, line, lineno)?;
    }
    context.into_report(TOOL_PREFIX, path.display().to_string())
}

fn ingest_nuclei_line(
    context: &mut ReconImportContext<'_>,
    line: &str,
    lineno: usize,
) -> Result<()> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let entry: Value = serde_json::from_str(trimmed)
        .with_context(|| format!("nuclei JSONL line {} is not valid JSON", lineno + 1))?;
    let host_value = nuclei_host(&entry);
    if let Some(host) = host_value.as_deref() {
        if !context.admit_host(host) {
            return Ok(());
        }
    }
    persist_nuclei_entry(context, &entry, host_value.as_deref())
}

fn nuclei_host(entry: &Value) -> Option<String> {
    entry
        .get("host")
        .or_else(|| entry.get("matched-at"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn persist_nuclei_entry(
    context: &mut ReconImportContext<'_>,
    entry: &Value,
    host_value: Option<&str>,
) -> Result<()> {
    let host_id = match host_value {
        Some(host) => Some(
            context
                .store
                .upsert_host(
                    &context.workspace_id,
                    host,
                    Some(host),
                    "alive",
                    json!({
                        "discoveredBy": TOOL_PREFIX,
                        "discoveredAt": now_isoish(),
                    }),
                )?
                .id,
        ),
        None => None,
    };
    let template = entry
        .get("template-id")
        .or_else(|| entry.get("templateID"))
        .and_then(Value::as_str)
        .unwrap_or("nuclei");
    let note = context.store.create_note(
        &context.workspace_id,
        host_id.as_deref(),
        None,
        &format!("{TOOL_PREFIX}:{template}"),
        nuclei_note_payload(entry, template),
    )?;
    context.notes.push(note);
    Ok(())
}

fn nuclei_note_payload(entry: &Value, template: &str) -> Value {
    let severity = entry
        .pointer("/info/severity")
        .and_then(Value::as_str)
        .unwrap_or("info");
    json!({
        "template": template,
        "severity": severity,
        "matched_at": entry.get("matched-at").cloned().unwrap_or(Value::Null),
        "info": entry.get("info").cloned().unwrap_or(Value::Null),
        "raw": entry.clone(),
    })
}
