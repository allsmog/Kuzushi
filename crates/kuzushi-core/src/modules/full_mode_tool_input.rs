use super::*;

pub(crate) fn full_mode_config_from_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::capabilities::full_mode_multi::FullModeConfig> {
    Ok(crate::capabilities::full_mode_multi::FullModeConfig {
        workspace_root: resolve_tool_target(input, ctx)?,
        max_tokens_per_chunk: full_mode_max_tokens(input),
        deposit_usd_per_chunk: full_mode_deposit(input),
        include_extensions: Vec::new(),
        language: full_mode_language(input)?,
        dry_run: full_mode_dry_run(input),
        scope_files: full_mode_scope_files(input, ctx)?,
        failed_chunk_ids: full_mode_failed_chunk_ids(input)?,
        auto_triage: input
            .get("autoTriage")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        auto_triage_max_steps: input
            .get("autoTriageMaxSteps")
            .and_then(Value::as_u64)
            .map(|v| v as u32),
        auto_triage_deposit_usd: input.get("autoTriageDepositUsd").and_then(Value::as_f64),
        run_budget_usd: full_mode_run_budget(input)?,
        reuse_cached_chunks: input
            .get("reuseCachedChunks")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        prefilter_model: input
            .get("prefilterModel")
            .and_then(Value::as_str)
            .map(str::to_string),
        prefilter_skip_below: full_mode_prefilter_skip_below(input)?,
    })
}

fn full_mode_prefilter_skip_below(input: &Value) -> Result<Option<u8>> {
    let Some(raw) = input.get("prefilterSkipBelow") else {
        return Ok(None);
    };
    let threshold = raw.as_u64().filter(|value| *value <= 10).ok_or_else(|| {
        anyhow::anyhow!("full-mode:hunt prefilterSkipBelow must be an integer 0-10, got {raw}")
    })?;
    Ok(Some(threshold as u8))
}

fn full_mode_run_budget(input: &Value) -> Result<Option<f64>> {
    let Some(budget) = input.get("budgetUsd").and_then(Value::as_f64) else {
        return Ok(None);
    };
    anyhow::ensure!(
        budget.is_finite() && budget > 0.0,
        "full-mode:hunt budgetUsd must be a positive number, got {budget}"
    );
    Ok(Some(budget))
}

pub(crate) fn full_mode_language(
    input: &Value,
) -> Result<crate::capabilities::full_mode_multi::FullModeLanguage> {
    match input
        .get("language")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("c") | None => Ok(crate::capabilities::full_mode_multi::FullModeLanguage::C),
        Some("unknown") => Ok(crate::capabilities::full_mode_multi::FullModeLanguage::Unknown),
        Some(other) => anyhow::bail!("full-mode:hunt: unknown language {other:?}"),
    }
}

pub(crate) fn full_mode_max_tokens(input: &Value) -> usize {
    input
        .get("maxTokensPerChunk")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(12_000)
}

pub(crate) fn full_mode_deposit(input: &Value) -> f64 {
    input
        .get("depositUsdPerChunk")
        .and_then(Value::as_f64)
        .unwrap_or(2.0)
}

pub(crate) fn full_mode_failed_chunk_ids(input: &Value) -> Result<Option<Vec<u32>>> {
    let Some(raw) = input.get("failedChunkIds") else {
        return Ok(None);
    };
    let mut ids = match raw {
        Value::String(csv) => csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(parse_failed_chunk_id)
            .collect::<Result<Vec<_>>>()?,
        Value::Array(values) => values
            .iter()
            .map(parse_failed_chunk_id_value)
            .collect::<Result<Vec<_>>>()?,
        other => anyhow::bail!(
            "full-mode:hunt failedChunkIds must be a comma-separated string or array, got {other}"
        ),
    };
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ids))
    }
}

fn parse_failed_chunk_id(raw: &str) -> Result<u32> {
    raw.parse::<u32>()
        .map_err(|_| anyhow::anyhow!("full-mode:hunt failedChunkIds has non-integer value {raw:?}"))
}

fn parse_failed_chunk_id_value(value: &Value) -> Result<u32> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| {
                anyhow::anyhow!("full-mode:hunt failedChunkIds has out-of-range value {number}")
            }),
        Value::String(raw) => parse_failed_chunk_id(raw.trim()),
        other => anyhow::bail!("full-mode:hunt failedChunkIds has invalid array value {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::full_mode_failed_chunk_ids;
    use serde_json::json;

    #[test]
    fn parses_csv_failed_chunk_ids() {
        let input = json!({"failedChunkIds": "3, 7, 7, 11"});
        assert_eq!(
            full_mode_failed_chunk_ids(&input).expect("csv parse should succeed"),
            Some(vec![3, 7, 11])
        );
    }

    #[test]
    fn parses_array_failed_chunk_ids() {
        let input = json!({"failedChunkIds": [11, "3", 7, "7"]});
        assert_eq!(
            full_mode_failed_chunk_ids(&input).expect("array parse should succeed"),
            Some(vec![3, 7, 11])
        );
    }
}
