use super::*;

pub(crate) struct NdiffFixPatternSource {
    pub(crate) record: Option<CveRecord>,
    pub(crate) patch_text: String,
    pub(crate) patch_url: String,
}

pub(crate) enum NdiffFixPatternSourceResolution {
    Ready(NdiffFixPatternSource),
    Rejected(Value),
}

pub(crate) fn resolve_ndiff_fix_pattern_source(
    input: &Value,
) -> Result<NdiffFixPatternSourceResolution> {
    let id = ndiff_fix_pattern_id(input);
    let mut source = initial_ndiff_fix_pattern_source(input);
    if source.patch_text.trim().is_empty() {
        if let Some(response) = resolve_missing_ndiff_patch_source(input, &id, &mut source)? {
            return Ok(NdiffFixPatternSourceResolution::Rejected(response));
        }
    }
    if source.patch_text.trim().is_empty() {
        return Ok(NdiffFixPatternSourceResolution::Rejected(
            unresolved_ndiff_patch_response(),
        ));
    }
    Ok(NdiffFixPatternSourceResolution::Ready(source))
}

fn resolve_missing_ndiff_patch_source(
    input: &Value,
    id: &Option<String>,
    source: &mut NdiffFixPatternSource,
) -> Result<Option<Value>> {
    if let Some(response) = resolve_local_ndiff_patch_source(input, id, source)? {
        return Ok(Some(response));
    }
    fetch_ndiff_patch_source(input, source)
}

fn resolve_local_ndiff_patch_source(
    input: &Value,
    id: &Option<String>,
    source: &mut NdiffFixPatternSource,
) -> Result<Option<Value>> {
    if let Some(response) = missing_ndiff_fix_pattern_source(id, source) {
        return Ok(Some(response));
    }
    apply_ndiff_advisory_source_if_present(id, input, source)
}

fn apply_ndiff_advisory_source_if_present(
    id: &Option<String>,
    input: &Value,
    source: &mut NdiffFixPatternSource,
) -> Result<Option<Value>> {
    let Some(id) = id.as_deref() else {
        return Ok(None);
    };
    apply_ndiff_advisory_source(id, input, source)
}

pub(crate) fn ndiff_fix_pattern_id(input: &Value) -> Option<String> {
    input
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn initial_ndiff_fix_pattern_source(input: &Value) -> NdiffFixPatternSource {
    NdiffFixPatternSource {
        record: None,
        patch_text: string_field(input, &["patchText", "patch_text"]).unwrap_or_default(),
        patch_url: string_field(input, &["patchUrl", "patch_url"]).unwrap_or_default(),
    }
}

pub(crate) fn string_field(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| input.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

pub(crate) fn missing_ndiff_fix_pattern_source(
    id: &Option<String>,
    source: &NdiffFixPatternSource,
) -> Option<Value> {
    if id.is_none() && source.patch_url.trim().is_empty() {
        return Some(crate::module_result::failed_output_result(
            "ndiff:extract-fix-pattern rejected input",
            "ndiff:extract-fix-pattern requires at least one of: id, patchText, or patchUrl.",
            json!({ "reason": "missing-source" }),
        ));
    }
    None
}

pub(crate) fn apply_ndiff_advisory_source(
    id: &str,
    input: &Value,
    source: &mut NdiffFixPatternSource,
) -> Result<Option<Value>> {
    let found = match fetch_cve_or_advisory(id, input) {
        Ok(found) => found,
        Err(error) => return Ok(Some(ndiff_advisory_fetch_error(id, error))),
    };
    apply_optional_ndiff_advisory(source, found);
    Ok(None)
}

fn apply_optional_ndiff_advisory(source: &mut NdiffFixPatternSource, found: Option<CveRecord>) {
    if let Some(found) = found {
        apply_found_ndiff_advisory(source, found);
    }
}

fn ndiff_advisory_fetch_error(id: &str, error: anyhow::Error) -> Value {
    crate::module_result::failed_output_result(
        "ndiff:extract-fix-pattern advisory fetch failed",
        format!("Could not fetch {id}: {error:#}"),
        json!({ "id": id, "reason": "advisory-fetch-error" }),
    )
}

pub(crate) fn apply_found_ndiff_advisory(source: &mut NdiffFixPatternSource, found: CveRecord) {
    if source.patch_url.trim().is_empty() {
        source.patch_url = choose_primary_patch_url(&found).unwrap_or_default();
    }
    source.record = Some(found);
}

pub(crate) fn fetch_ndiff_patch_source(
    input: &Value,
    source: &mut NdiffFixPatternSource,
) -> Result<Option<Value>> {
    if source.patch_url.trim().is_empty() {
        return Ok(None);
    }
    let result = fetch_patch_text(&source.patch_url, input);
    Ok(apply_ndiff_patch_fetch_result(input, source, result))
}

fn apply_ndiff_patch_fetch_result(
    input: &Value,
    source: &mut NdiffFixPatternSource,
    result: Result<Option<String>>,
) -> Option<Value> {
    match result {
        Ok(result) => apply_ndiff_patch_fetch_success(input, source, result),
        Err(error) => Some(ndiff_patch_fetch_error(&source.patch_url, error)),
    }
}

fn apply_ndiff_patch_fetch_success(
    input: &Value,
    source: &mut NdiffFixPatternSource,
    result: Option<String>,
) -> Option<Value> {
    let Some(text) = result else {
        return Some(unfetched_ndiff_patch_response(&source.patch_url, input));
    };
    source.patch_text = text;
    None
}

fn ndiff_patch_fetch_error(patch_url: &str, error: anyhow::Error) -> Value {
    crate::module_result::failed_output_result(
        "ndiff:extract-fix-pattern patch fetch failed",
        format!("Could not fetch patch content from {patch_url}: {error:#}"),
        json!({ "patchUrl": patch_url, "reason": "patch-fetch-error" }),
    )
}

pub(crate) fn unresolved_ndiff_patch_response() -> Value {
    crate::module_result::failed_output_result(
        "ndiff:extract-fix-pattern patch content unavailable",
        "ndiff:extract-fix-pattern could not resolve any patch content to analyze.",
        json!({ "reason": "unresolved-patch-content" }),
    )
}

pub(crate) fn unfetched_ndiff_patch_response(patch_url: &str, input: &Value) -> Value {
    let output = format!(
        "Could not fetch patch content from {}{}.",
        patch_url,
        if input.get("offline").and_then(Value::as_bool).unwrap_or(false) {
            " (offline mode)"
        } else {
            ""
        }
    );
    crate::module_result::failed_output_result(
        "ndiff:extract-fix-pattern patch content unavailable",
        output,
        json!({ "patchUrl": patch_url, "reason": "patch-content-unavailable" }),
    )
}

pub(crate) fn ndiff_fix_pattern_response(
    source: NdiffFixPatternSource,
    pattern: Value,
    cost: crate::runtime::RuntimeCostReport,
) -> Result<Value> {
    let object = pattern
        .as_object()
        .context("ndiff:extract-fix-pattern output parse failed: expected a JSON object")?;
    let output = ndiff_fix_pattern_output(object);

    let data = json!({
        "advisory": source.record,
        "pattern": pattern,
        "patchUrl": source.patch_url,
    });
    let mut result =
        crate::module_result::completed_output_result("ndiff:extract-fix-pattern completed", output, data);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}
