use super::*;

pub(crate) fn persist_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<PersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;
    Ok(Some(PersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

pub(crate) fn fetch_cve_or_advisory(id: &str, input: &Value) -> Result<Option<CveRecord>> {
    record_from_input(id, input)?.map_or_else(
        || fetch_online_cve_or_advisory(id, input),
        |record| Ok(Some(record)),
    )
}

pub(crate) fn fetch_online_cve_or_advisory(id: &str, input: &Value) -> Result<Option<CveRecord>> {
    if input_is_offline(input) {
        return Ok(None);
    }
    fetch_advisory_from_source(advisory_source_for_id(id)?, id, input)
}

pub(crate) fn fetch_advisory_from_source(
    source: AdvisorySource,
    id: &str,
    input: &Value,
) -> Result<Option<CveRecord>> {
    match source {
        AdvisorySource::Nvd => fetch_nvd_advisory(id, input),
        AdvisorySource::Ghsa => fetch_ghsa_advisory(id, input),
    }
}

pub(crate) fn fetch_nvd_advisory(id: &str, input: &Value) -> Result<Option<CveRecord>> {
    let raw = curl_json(&nvd_advisory_url(id), input, "ndiff:fetch-cve")?;
    Ok(map_nvd_record(id, raw))
}

pub(crate) fn fetch_ghsa_advisory(id: &str, input: &Value) -> Result<Option<CveRecord>> {
    let normalized = id.to_ascii_lowercase();
    let raw = curl_json(&ghsa_advisory_url(&normalized), input, "ndiff:fetch-cve")?;
    Ok(Some(map_ghsa_record(&normalized, raw)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdvisorySource {
    Nvd,
    Ghsa,
}

pub(crate) fn advisory_source_for_id(id: &str) -> Result<AdvisorySource> {
    if id.to_ascii_uppercase().starts_with("CVE-") {
        return Ok(AdvisorySource::Nvd);
    }
    if id.to_ascii_lowercase().starts_with("ghsa-") {
        return Ok(AdvisorySource::Ghsa);
    }
    anyhow::bail!("Unrecognized advisory ID: {id:?} (expected CVE-* or GHSA-*)")
}

pub(crate) fn nvd_advisory_url(id: &str) -> String {
    format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
        shell_escape_url(id)
    )
}

pub(crate) fn ghsa_advisory_url(id: &str) -> String {
    format!("https://api.github.com/advisories/{}", shell_escape_url(id))
}

pub(crate) fn record_from_input(id: &str, input: &Value) -> Result<Option<CveRecord>> {
    if let Some(Value::Object(record)) = input.get("record") {
        return Ok(Some(serde_json::from_value(Value::Object(record.clone()))?));
    }
    let Some(fixtures) = input.get("fixtures").and_then(Value::as_object) else {
        return Ok(None);
    };
    let candidates = [
        id.to_string(),
        id.to_ascii_uppercase(),
        id.to_ascii_lowercase(),
    ];
    for key in candidates {
        if let Some(value) = fixtures.get(&key) {
            return Ok(Some(serde_json::from_value(value.clone()).with_context(
                || format!("Could not parse offline advisory fixture {key}"),
            )?));
        }
    }
    Ok(None)
}

pub(crate) fn input_is_offline(input: &Value) -> bool {
    input
        .get("offline")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
