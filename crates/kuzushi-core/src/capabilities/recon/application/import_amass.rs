use super::*;

const TOOL: &str = "recon:import-amass";

/// Import an Amass JSONL recon dump (`amass enum -json out.jsonl`) into
/// the recon store as `ReconHost` rows. Hosts `.kuzushi/scope.toml` puts
/// out of scope are skipped, and parsed rows without a usable `name` are
/// counted separately so neither class of refusal disappears from the report.
pub(crate) fn run_recon_import_amass(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message("recon:import"))?;
    let (path, body) = read_jsonl_path(input, "recon:import amass needs a `path` field")?;
    let mut context = ReconImportContext::open(workspace)?;
    let record_count = body.lines().filter(|line| !line.trim().is_empty()).count();
    for (lineno, line) in body.lines().enumerate() {
        ingest_amass_line(&mut context, line, lineno)?;
    }
    let host_count = context.hosts.len();
    let skipped = context.skipped_out_of_scope;
    let skipped_unusable = context.skipped_unusable;
    context.notes.push(context.store.create_note(
        &context.workspace_id,
        None,
        None,
        TOOL,
        json!({
            "path": path.display().to_string(),
            "records": record_count,
            "count": host_count,
            "skippedOutOfScope": skipped,
            "skippedUnusable": skipped_unusable,
        }),
    )?);
    context.into_report(TOOL, path.display().to_string())
}

fn ingest_amass_line(
    context: &mut ReconImportContext<'_>,
    line: &str,
    lineno: usize,
) -> Result<()> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let entry: Value = serde_json::from_str(trimmed)
        .with_context(|| format!("amass JSONL line {} is not valid JSON", lineno + 1))?;
    let Some(name) = amass_name(&entry) else {
        context.skip_unusable_host();
        return Ok(());
    };
    if !context.admit_host(name) {
        return Ok(());
    }
    let host = context.store.upsert_host(
        &context.workspace_id,
        name,
        Some(name),
        "alive",
        amass_host_metadata(&entry),
    )?;
    context.hosts.push(host);
    Ok(())
}

fn amass_name(entry: &Value) -> Option<&str> {
    entry
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn amass_host_metadata(entry: &Value) -> Value {
    json!({
        "discoveredBy": TOOL,
        "discoveredAt": now_isoish(),
        "domain": entry.get("domain").and_then(Value::as_str),
        "sources": entry.get("sources").cloned().unwrap_or(Value::Null),
        "addresses": entry.get("addresses").cloned().unwrap_or(Value::Null),
        "raw": entry.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_nonempty_amass_name_is_addressable() {
        assert_eq!(amass_name(&json!({"name": " api.example.com "})), Some("api.example.com"));
        assert_eq!(amass_name(&json!({"name": ""})), None);
        assert_eq!(amass_name(&json!({"name": "   "})), None);
        assert_eq!(amass_name(&json!({"domain": "example.com"})), None);
    }
}
