use super::*;

#[derive(Debug, Clone)]
pub(in crate::modules) struct TriageRunInput {
    pub(in crate::modules) fingerprints: Option<Vec<String>>,
    pub(in crate::modules) prompt_template: Option<String>,
    pub(in crate::modules) scan_id: Option<String>,
    pub(in crate::modules) concurrency: usize,
    pub(in crate::modules) cost_cap_usd: Option<f64>,
    pub(in crate::modules) prefilter_threshold: i64,
    pub(in crate::modules) stage2_tier: ModelTier,
    pub(in crate::modules) model: Option<String>,
    pub(in crate::modules) retriage: bool,
    pub(in crate::modules) votes: usize,
}

impl TriageRunInput {
    pub(in crate::modules) fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        Ok(Self {
            fingerprints: parse_triage_fingerprints(input)?,
            prompt_template: parse_triage_prompt_template(input, cwd)?,
            scan_id: parse_triage_scan_id(input)?,
            concurrency: parse_triage_concurrency(input)?,
            cost_cap_usd: parse_triage_cost_cap_usd(input)?,
            prefilter_threshold: parse_triage_prefilter_threshold(input),
            stage2_tier: parse_triage_stage2_tier(input)?,
            model: optional_nonempty_string(input, "model")?,
            retriage: parse_triage_retriage(input),
            votes: parse_triage_votes(input)?,
        })
    }
}

pub(in crate::modules) const MAX_TRIAGE_VOTES: usize = 5;

pub(in crate::modules) fn parse_triage_votes(input: &Value) -> Result<usize> {
    let Some(value) = input.get("votes") else {
        return Ok(1);
    };
    let votes = value
        .as_u64()
        .with_context(|| format!("triage:run votes must be a positive integer, got {value}"))?;
    anyhow::ensure!(
        (1..=MAX_TRIAGE_VOTES as u64).contains(&votes),
        "triage:run votes must be between 1 and {MAX_TRIAGE_VOTES}, got {votes}"
    );
    Ok(votes as usize)
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

pub(in crate::modules) fn parse_triage_retriage(input: &Value) -> bool {
    input
        .get("retriage")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
