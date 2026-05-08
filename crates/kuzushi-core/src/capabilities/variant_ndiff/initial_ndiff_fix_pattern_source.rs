use super::*;

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
        return Some(json!({
            "ok": false,
            "output": "ndiff:extract-fix-pattern requires at least one of: id, patchText, or patchUrl.",
        }));
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
    json!({
        "ok": false,
        "output": format!("Could not fetch {id}: {error:#}"),
    })
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
    json!({
        "ok": false,
        "output": format!("Could not fetch patch content from {patch_url}: {error:#}"),
    })
}

pub(crate) fn unresolved_ndiff_patch_response() -> Value {
    json!({
        "ok": false,
        "output": "ndiff:extract-fix-pattern could not resolve any patch content to analyze.",
    })
}

pub(crate) fn unfetched_ndiff_patch_response(patch_url: &str, input: &Value) -> Value {
    json!({
        "ok": false,
        "output": format!(
            "Could not fetch patch content from {}{}.",
            patch_url,
            if input.get("offline").and_then(Value::as_bool).unwrap_or(false) {
                " (offline mode)"
            } else {
                ""
            }
        ),
    })
}

pub(crate) fn ndiff_fix_pattern_response(
    source: NdiffFixPatternSource,
    pattern: Value,
) -> Result<Value> {
    let object = pattern
        .as_object()
        .context("ndiff:extract-fix-pattern output parse failed: expected a JSON object")?;
    let output = ndiff_fix_pattern_output(object);

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "advisory": source.record,
            "pattern": pattern,
            "patchUrl": source.patch_url,
        },
        "costUsd": 0.0,
    }))
}
