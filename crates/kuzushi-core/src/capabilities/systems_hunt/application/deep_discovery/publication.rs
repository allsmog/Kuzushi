use super::*;
mod copy;

pub(super) fn finalize(
    root: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    ready: &crate::findings::FindingSourceSnapshot,
    result: &mut Value,
) -> Result<()> {
    if result["status"] == "failed" {
        return Ok(());
    }
    if let Some(reason) = hold_reason(ctx, result) {
        withhold(result, reason, false);
        return Ok(());
    }
    let report: SystemsHuntReport = serde_json::from_value(result["data"].clone())?;
    let sources = match prepare_publication(input, ctx, ready, result, &report.findings) {
        Ok(source) => source,
        Err(error) => {
            withhold(result, &format!("Source capture refused publication: {error:#}. Historical candidates remain in Replay; no observations were inserted by this action."), false);
            return Ok(());
        }
    };
    match persist_captured(root, &report.findings, ctx, &sources) {
        Ok(persisted) => {
            result["data"]["persisted"] = json!(persisted);
            result["data"]["publicationStatus"] = json!("published");
            result["output"] = json!(copy::published_output(result["output"].as_str().unwrap_or(""), report.count));
        }
        Err(error) => withhold(result, &format!("Ledger publication failed: {error:#}. Some observations may already exist; inspect the findings ledger before retrying."), true),
    }
    Ok(())
}

fn hold_reason(ctx: &ToolExecutionContext<'_>, result: &Value) -> Option<&'static str> {
    if ctx.is_cancelled() {
        return Some("Cancellation requested before ledger publication. Historical candidates remain in Replay; none were published by this action.");
    }
    if result["data"]["sourceCheckCurrent"] != true {
        return Some("Source changed before ledger publication. Historical candidates remain in Replay; none were published by this action.");
    }
    None
}

fn withhold(result: &mut Value, reason: &str, partial_ledger_possible: bool) {
    result["data"]["unpublishedCandidates"] = result["data"]["findings"].clone();
    result["data"]["findings"] = json!([]);
    result["data"]["count"] = json!(0);
    result["data"]["publicationStatus"] = json!("withheld");
    result["data"]["partialLedgerPossible"] = json!(partial_ledger_possible);
    result["status"] = json!("partial");
    result["summary"] = json!(reason);
    result["output"] = json!(copy::withheld_output(
        result["output"].as_str().unwrap_or(""),
        reason,
        partial_ledger_possible
    ));
    let mut warnings = result["warnings"].as_array().cloned().unwrap_or_default();
    warnings.push(json!(reason));
    result["warnings"] = json!(warnings);
}

fn prepare_publication(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    ready: &crate::findings::FindingSourceSnapshot,
    result: &mut Value,
    findings: &[Finding],
) -> Result<crate::findings::CapturedFindingSources> {
    let maximum = input::Limits::parse(input)?.max_snapshot_bytes;
    let sources = captured_sources(ctx, ready, result, findings, maximum)?;
    let (files, bytes) = sources.captured_counts();
    result["data"]["publicationSource"] = json!({"kind":"authenticated captured files",
        "snapshotHash":result["data"]["snapshotHash"],"treeHash":result["data"]["treeHash"],
        "capturedFiles":files,"capturedBytes":bytes,"maxSnapshotBytes":maximum});
    result["output"] = json!(format!("{}\nRetained source: {files} cited files, {}; capture limit {}. Supplied prefixes are retained in the input document.", result["output"].as_str().unwrap_or(""), copy::bytes(bytes), copy::bytes(maximum)));
    Ok(sources)
}

fn captured_sources(
    ctx: &ToolExecutionContext<'_>,
    ready: &crate::findings::FindingSourceSnapshot,
    result: &Value,
    findings: &[Finding],
    maximum: usize,
) -> Result<crate::findings::CapturedFindingSources> {
    let supplied = result["data"]["frozenInput"]["sources"]
        .as_array()
        .context("Frozen discovery sources are missing")?
        .iter()
        .map(|row| {
            Ok((
                row["path"]
                    .as_str()
                    .context("Source path is missing")?
                    .into(),
                row["text"]
                    .as_str()
                    .context("Source text is missing")?
                    .into(),
            ))
        })
        .collect::<Result<BTreeMap<String, String>>>()?;
    ready.capture(&supplied, findings, maximum, &|| ctx.is_cancelled())
}

fn persist_captured(
    root: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
    source: &crate::findings::CapturedFindingSources,
) -> Result<Option<SystemsHuntPersistedRun>> {
    let workspace = ctx.workspace.context("Active repository is missing")?;
    let store = ctx
        .findings_store
        .context("Active findings ledger is missing")?;
    let run_id = ctx.finding_run_id();
    store.with_run_lifecycle(&run_id, root, || {
        for finding in findings {
            anyhow::ensure!(
                !ctx.is_cancelled(),
                "Discovery canceled during publication; inspect any already recorded observations"
            );
            store.insert_finding_with_sources(&run_id, finding, source)?;
        }
        Ok(((), findings.len()))
    })?;
    Ok(Some(SystemsHuntPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}
