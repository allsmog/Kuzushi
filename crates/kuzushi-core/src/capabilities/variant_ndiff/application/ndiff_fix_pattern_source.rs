use super::*;

pub(crate) struct NdiffFixPatternSource {
    pub(crate) record: Option<CveRecord>,
    pub(crate) patch_text: String,
    pub(crate) patch_url: String,
    pub(crate) source_kind: &'static str,
    pub(crate) max_patch_bytes: usize,
    pub(crate) max_source_bytes: usize,
}

pub(crate) enum NdiffFixPatternSourceResolution {
    Ready(NdiffFixPatternSource),
    Rejected(Value),
}

#[cfg(test)]
pub(crate) fn resolve_ndiff_fix_pattern_source(
    input: &Value,
) -> Result<NdiffFixPatternSourceResolution> {
    resolve_ndiff_source(input, None)
}

pub(crate) fn resolve_ndiff_source_for_target(
    input: &Value,
    target: &Path,
) -> Result<NdiffFixPatternSourceResolution> {
    resolve_ndiff_source(input, Some(target))
}

fn resolve_ndiff_source(
    input: &Value,
    target: Option<&Path>,
) -> Result<NdiffFixPatternSourceResolution> {
    let mut source = match checked_initial_source(input) {
        Ok(source) => source,
        Err(response) => return Ok(NdiffFixPatternSourceResolution::Rejected(response)),
    };
    load_explicit_diff_file(input, target, &mut source)?;
    let id = ndiff_fix_pattern_id(input);
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
    anyhow::ensure!(source.patch_text.len() <= source.max_patch_bytes, "Existing diff exceeds maxPatchBytes; narrow the supplied content or approve a larger declared bound");
    Ok(NdiffFixPatternSourceResolution::Ready(source))
}

fn load_explicit_diff_file(
    input: &Value,
    target: Option<&Path>,
    source: &mut NdiffFixPatternSource,
) -> Result<()> {
    if !source.patch_text.trim().is_empty() {
        return Ok(());
    }
    let Some(path) = string_field(input, &["patchPath", "patch_path"]) else {
        return Ok(());
    };
    let root = target.context("Diff file input requires an explicit workspace target")?;
    source.patch_text =
        crate::bounded_file::read_utf8_text_within(root, Path::new(&path), source.max_patch_bytes)
            .context("Could not read the supplied existing diff within the selected target")?;
    source.source_kind = "supplied-file";
    Ok(())
}

fn checked_initial_source(input: &Value) -> std::result::Result<NdiffFixPatternSource, Value> {
    validate_metadata_input(input).map_err(rejected_ndiff_source_input)?;
    match invalid_ndiff_record_response(input) {
        Some(response) => Err(response),
        None => checked_source_contents(input).map_err(rejected_ndiff_source_input),
    }
}

fn rejected_ndiff_source_input(error: anyhow::Error) -> Value {
    crate::module_result::failed_output_result(
        "Advisory-pattern source rejected",
        format!("Could not use supplied diff context: {error:#}"),
        json!({"reason":"invalid-source"}),
    )
}

fn checked_source_contents(input: &Value) -> Result<NdiffFixPatternSource> {
    let max_patch_bytes =
        ndiff_query_limit(input, "maxPatchBytes", 256 * 1024, 1..=8 * 1024 * 1024)?;
    let max_source_bytes = ndiff_query_limit(input, "maxSourceBytes", 18000, 256..=128 * 1024)?;
    let text = input
        .get("patchText")
        .or_else(|| input.get("patch_text"))
        .and_then(Value::as_str)
        .unwrap_or("");
    anyhow::ensure!(
        text.len() <= max_patch_bytes,
        "Supplied diff exceeds maxPatchBytes"
    );
    let mut source = initial_ndiff_fix_pattern_source(input);
    source.max_patch_bytes = max_patch_bytes;
    source.max_source_bytes = max_source_bytes;
    Ok(source)
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

/// A caller that already fetched the advisory (`threat-intel:harvest` after
/// `ndiff:fetch-cve`) passes it as `record`; its primary patch reference
/// stands in for an explicit `patchUrl`.
pub(crate) fn initial_ndiff_fix_pattern_source(input: &Value) -> NdiffFixPatternSource {
    let mut source = NdiffFixPatternSource {
        record: None,
        patch_text: string_field(input, &["patchText", "patch_text"]).unwrap_or_default(),
        patch_url: string_field(input, &["patchUrl", "patch_url"]).unwrap_or_default(),
        source_kind: "supplied-text",
        max_patch_bytes: 256 * 1024,
        max_source_bytes: 18000,
    };
    if let Some(record) = input_advisory_record(input) {
        apply_found_ndiff_advisory(&mut source, record);
    }
    source
}

/// A `record` that is present but not an advisory record is refused rather
/// than ignored.
fn invalid_ndiff_record_response(input: &Value) -> Option<Value> {
    let error = serde_json::from_value::<CveRecord>(input.get("record")?.clone()).err()?;
    Some(crate::module_result::failed_output_result(
        "ndiff:extract-fix-pattern rejected input",
        format!("ndiff:extract-fix-pattern record is not an advisory record: {error}"),
        json!({ "reason": "invalid-record" }),
    ))
}

fn input_advisory_record(input: &Value) -> Option<CveRecord> {
    serde_json::from_value(input.get("record")?.clone()).ok()
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
            "ndiff:extract-fix-pattern requires at least one of: id, a record with a patch reference, patchText, or patchUrl.",
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
    source.source_kind = "reference-content";
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
        if input
            .get("offline")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
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
    let receipt = ndiff_diff_source_receipt(&source);
    let output = format!("Unaccepted advisory-pattern draft. Source claims require review before reuse.\nDiff context: {} of {} supplied bytes; {} bytes omitted.\n{}",receipt["includedBytes"],receipt["bytes"],receipt["omittedBytes"],ndiff_fix_pattern_output(object));

    let data = json!({
        "advisory": source.record,
        "pattern": pattern,
        "patchUrl": source.patch_url,
        "draft": true,
        "accepted": false,
        "contextActivated": false,
        "sourceReceipt": receipt,
    });
    let mut result = ndiff_pattern_draft_result(output, data);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

fn ndiff_diff_source_receipt(source: &NdiffFixPatternSource) -> Value {
    let included = ndiff_diff_prefix(&source.patch_text, source.max_source_bytes).len();
    json!({"schemaVersion":1,"kind":source.source_kind,"digest":crate::run_lifecycle::sha256_content_digest(source.patch_text.as_bytes()),
        "bytes":source.patch_text.len(),"includedBytes":included,"omittedBytes":source.patch_text.len()-included,
        "complete":included==source.patch_text.len(),"sourceVerified":false})
}

fn ndiff_pattern_draft_result(output: String, data: Value) -> Value {
    if data["sourceReceipt"]["complete"] == false {
        return crate::module_result::partial_output_result(
            "Advisory-pattern draft: unaccepted; supplied diff excerpted",
            output,
            vec![
                json!({"code":"diff-excerpted","message":"The model received only the disclosed existing diff excerpt. Review the omitted material before reusing this unaccepted draft."}),
            ],
            data,
        );
    }
    crate::module_result::completed_output_result(
        "Advisory-pattern draft: unaccepted; source claims require review",
        output,
        data,
    )
}
