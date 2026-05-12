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
    // Try each candidate source in priority order. The first one to
    // return a usable record wins. A source that errors at the
    // transport layer (curl missing, malformed JSON) bubbles up as a
    // hard error — sources that simply return empty bodies (no data
    // for this id) fall through to the next source.
    let candidates = advisory_sources_for_id(id);
    fetch_first_advisory_record(candidates, id, input)
}

fn fetch_first_advisory_record(
    sources: Vec<AdvisorySource>,
    id: &str,
    input: &Value,
) -> Result<Option<CveRecord>> {
    fetch_next_advisory_record(&sources, id, input, None)
}

fn fetch_next_advisory_record(
    sources: &[AdvisorySource],
    id: &str,
    input: &Value,
    mut last_error: Option<anyhow::Error>,
) -> Result<Option<CveRecord>> {
    let Some((source, remaining)) = sources.split_first() else {
        return advisory_fetch_result(last_error);
    };
    fetch_or_remember_advisory_error(*source, id, input, &mut last_error)?.map_or_else(
        || fetch_next_advisory_record(remaining, id, input, last_error),
        |record| Ok(Some(record)),
    )
}

fn advisory_fetch_result(last_error: Option<anyhow::Error>) -> Result<Option<CveRecord>> {
    match last_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

fn fetch_or_remember_advisory_error(
    source: AdvisorySource,
    id: &str,
    input: &Value,
    last_error: &mut Option<anyhow::Error>,
) -> Result<Option<CveRecord>> {
    match fetch_advisory_from_source(source, id, input) {
        Ok(record) => Ok(record),
        Err(err) => {
            *last_error = Some(err);
            Ok(None)
        }
    }
}

pub(crate) fn fetch_advisory_from_source(
    source: AdvisorySource,
    id: &str,
    input: &Value,
) -> Result<Option<CveRecord>> {
    advisory_fetcher(source)(id, input)
}

type AdvisoryFetcher = fn(&str, &Value) -> Result<Option<CveRecord>>;

fn advisory_fetcher(source: AdvisorySource) -> AdvisoryFetcher {
    const FETCHERS: &[(AdvisorySource, AdvisoryFetcher)] = &[
        (AdvisorySource::Nvd, fetch_nvd_advisory),
        (AdvisorySource::Ghsa, fetch_ghsa_advisory),
        (AdvisorySource::Osv, fetch_osv_advisory),
    ];
    FETCHERS
        .iter()
        .find_map(|(candidate, fetcher)| (*candidate == source).then_some(*fetcher))
        .unwrap_or(fetch_osv_advisory)
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

pub(crate) fn fetch_osv_advisory(id: &str, input: &Value) -> Result<Option<CveRecord>> {
    let raw = curl_json(&osv_advisory_url(id), input, "ndiff:fetch-cve")?;
    if raw.is_null() {
        return Ok(None);
    }
    Ok(Some(map_osv_record(id, raw)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdvisorySource {
    Nvd,
    Ghsa,
    Osv,
}

/// Pick the fallback chain for a given advisory id.
///
/// CVE-* IDs are present in both NVD and OSV. NVD is the authoritative
/// numbering authority but OSV often has fresher patch references; we
/// try NVD first, then OSV as a fallback.
/// GHSA-* IDs live in GitHub; OSV mirrors them with the upstream
/// classification, so OSV is the natural fallback when the GHSA REST
/// endpoint returns nothing.
/// Other prefixes (`PYSEC-`, `GO-`, `RUSTSEC-`, …) are OSV-native.
pub(crate) fn advisory_sources_for_id(id: &str) -> Vec<AdvisorySource> {
    let upper = id.to_ascii_uppercase();
    if upper.starts_with("CVE-") {
        return vec![AdvisorySource::Nvd, AdvisorySource::Osv];
    }
    if upper.starts_with("GHSA-") {
        return vec![AdvisorySource::Ghsa, AdvisorySource::Osv];
    }
    if upper.starts_with("PYSEC-")
        || upper.starts_with("GO-")
        || upper.starts_with("RUSTSEC-")
        || upper.starts_with("CARGO-")
        || upper.starts_with("MAL-")
        || upper.starts_with("OSV-")
    {
        return vec![AdvisorySource::Osv];
    }
    // Unknown prefix: still try OSV (it accepts any registered id),
    // but no upstream fallback.
    vec![AdvisorySource::Osv]
}

#[cfg(test)]
pub(crate) fn advisory_source_for_id(id: &str) -> Result<AdvisorySource> {
    advisory_sources_for_id(id).into_iter().next().with_context(|| {
        format!("Unrecognized advisory ID: {id:?} (expected CVE-*, GHSA-*, or OSV-supported prefix)")
    })
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

pub(crate) fn osv_advisory_url(id: &str) -> String {
    format!("https://api.osv.dev/v1/vulns/{}", shell_escape_url(id))
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
