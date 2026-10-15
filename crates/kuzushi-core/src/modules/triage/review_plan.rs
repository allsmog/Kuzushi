use super::*;

/// Freeze the existing selector to exact observations before work approval.
pub(crate) fn freeze_triage_review_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(Value, Vec<Finding>)> {
    let store = ctx
        .findings_store
        .context("review planning requires findings")?;
    let root = ctx
        .workspace
        .context("review planning requires a workspace")?
        .root();
    let selection = TriageRunInput::from_tool_input(input, root)?;
    let (findings, missing) = select_triage_findings(store, &selection)?;
    anyhow::ensure!(
        missing.is_empty(),
        "review selection contains missing observations"
    );
    anyhow::ensure!(
        (1..=100).contains(&findings.len()),
        "select 1 to 100 pending findings for this review plan"
    );
    let references = findings
        .iter()
        .map(exact_reference)
        .collect::<Result<Vec<_>>>()?;
    let frozen = bind_exact_selection(input, &selection, references)?;
    let exact = TriageRunInput::from_tool_input(&frozen, root)?;
    let (raw, missing) = select_triage_findings(store, &exact)?;
    anyhow::ensure!(
        missing.is_empty() && raw.len() == findings.len(),
        "review observation selection changed during preparation"
    );
    Ok((frozen, raw))
}

fn bind_exact_selection(
    input: &Value,
    selection: &TriageRunInput,
    references: Vec<String>,
) -> Result<Value> {
    let mut frozen = input.clone();
    let object = frozen
        .as_object_mut()
        .context("reviewInput must be an object")?;
    for key in [
        "fingerprint",
        "findingFingerprint",
        "fingerprints",
        "scanId",
        "scope",
    ] {
        object.remove(key);
    }
    object.insert("fingerprints".into(), json!(references));
    object.insert("scope".into(), json!("all"));
    object
        .entry("strategy")
        .or_insert_with(|| json!(if selection.deep { "deep" } else { "standard" }));
    Ok(frozen)
}

fn exact_reference(finding: &Finding) -> Result<String> {
    let id = finding
        .id
        .filter(|id| *id > 0)
        .context("review observation has no durable generation id")?;
    Ok(format!("generation:{id}"))
}
