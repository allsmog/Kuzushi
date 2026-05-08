use super::*;

#[derive(Debug, Clone)]
pub(in crate::modules) struct TriageRunInput {
    pub(in crate::modules) fingerprints: Option<Vec<String>>,
    pub(in crate::modules) batch_size: usize,
    pub(in crate::modules) prompt_template: Option<String>,
    pub(in crate::modules) scan_id: Option<String>,
    pub(in crate::modules) concurrency: usize,
    pub(in crate::modules) cost_cap_usd: Option<f64>,
    pub(in crate::modules) prefilter_threshold: i64,
    pub(in crate::modules) stage2_tier: ModelTier,
}

impl TriageRunInput {
    pub(in crate::modules) fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        Ok(Self {
            fingerprints: parse_triage_fingerprints(input)?,
            batch_size: parse_triage_batch_size(input)?,
            prompt_template: parse_triage_prompt_template(input, cwd)?,
            scan_id: parse_triage_scan_id(input)?,
            concurrency: parse_triage_concurrency(input)?,
            cost_cap_usd: parse_triage_cost_cap_usd(input)?,
            prefilter_threshold: parse_triage_prefilter_threshold(input),
            stage2_tier: parse_triage_stage2_tier(input)?,
        })
    }
}

pub(in crate::modules) fn parse_triage_fingerprints(input: &Value) -> Result<Option<Vec<String>>> {
    let mut fingerprints = Vec::new();
    push_primary_fingerprint(input, &mut fingerprints)?;
    extend_fingerprint_array(input, &mut fingerprints)?;
    Ok(nonempty_fingerprints(fingerprints))
}

pub(in crate::modules) fn push_primary_fingerprint(
    input: &Value,
    fingerprints: &mut Vec<String>,
) -> Result<()> {
    if let Some(fingerprint) = optional_nonempty_string(input, "fingerprint")? {
        fingerprints.push(fingerprint);
    }
    Ok(())
}

pub(in crate::modules) fn extend_fingerprint_array(
    input: &Value,
    fingerprints: &mut Vec<String>,
) -> Result<()> {
    let Some(values) = input.get("fingerprints") else {
        return Ok(());
    };
    let Value::Array(items) = values else {
        anyhow::bail!("triage:run fingerprints must be an array of strings");
    };
    for item in items {
        fingerprints.push(parse_fingerprint_entry(item)?);
    }
    Ok(())
}

pub(in crate::modules) fn parse_fingerprint_entry(item: &Value) -> Result<String> {
    let Some(value) = item
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        anyhow::bail!("triage:run fingerprints entries must be non-empty strings");
    };
    Ok(value.to_string())
}

pub(in crate::modules) fn nonempty_fingerprints(fingerprints: Vec<String>) -> Option<Vec<String>> {
    if fingerprints.is_empty() {
        None
    } else {
        Some(fingerprints)
    }
}

pub(in crate::modules) fn parse_triage_batch_size(input: &Value) -> Result<usize> {
    match input.get("batchSize").or_else(|| input.get("batch_size")) {
        Some(Value::Number(number)) => clamp_triage_batch_size(
            number
                .as_u64()
                .context("triage:run batchSize must be a positive integer")? as usize,
        ),
        Some(Value::String(value)) => clamp_triage_batch_size(
            value
                .parse::<usize>()
                .context("triage:run batchSize must be a positive integer")?,
        ),
        Some(_) => anyhow::bail!("triage:run batchSize must be a positive integer"),
        None => Ok(5),
    }
}

pub(in crate::modules) fn clamp_triage_batch_size(value: usize) -> Result<usize> {
    if value == 0 {
        anyhow::bail!("triage:run batchSize must be a positive integer");
    }
    Ok(value.min(500))
}
