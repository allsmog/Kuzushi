use super::*;

/// Finding selection scope: the active corpus across every run and tool
/// (default), or an explicitly requested latest/run-scoped projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::modules) enum TriageScope {
    Latest,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::modules) enum IdentityReconcilePolicy {
    Auto,
    Off,
}

impl IdentityReconcilePolicy {
    pub(in crate::modules) fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::modules) enum ModelDedupePolicy {
    Off,
    Manual,
    Auto,
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct TriageRunInput {
    pub(in crate::modules) fingerprints: Option<Vec<String>>,
    pub(in crate::modules) prompt_template: Option<String>,
    pub(in crate::modules) scan_id: Option<String>,
    pub(in crate::modules) scope: TriageScope,
    /// Classify with the code-reading deep auditor instead of the single-shot
    /// evidence-only call. Defaults to true for `scope=all` bulk triage,
    /// overridable with an explicit `strategy=standard`.
    pub(in crate::modules) deep: bool,
    pub(in crate::modules) concurrency: usize,
    pub(in crate::modules) cost_cap_usd: Option<f64>,
    pub(in crate::modules) prefilter_threshold: i64,
    pub(in crate::modules) stage2_tier: ModelTier,
    pub(in crate::modules) model: Option<String>,
    pub(in crate::modules) retriage: bool,
    pub(in crate::modules) identity_reconcile: IdentityReconcilePolicy,
    pub(in crate::modules) model_dedupe: ModelDedupePolicy,
    pub(in crate::modules) votes: usize,
    pub(in crate::modules) deep_tuning: DeepTriageTuning,
    /// Stable-key → reviewer-feedback note from stored suppressions.
    /// Populated during run preparation, never parsed from tool input.
    pub(in crate::modules) suppression_feedback: std::collections::BTreeMap<String, String>,
    /// Fingerprint → human-reviewed, shrunken advisory prior. Populated from
    /// persisted review history during run preparation; never tool input.
    pub(in crate::modules) reviewed_refutation_priors:
        std::collections::BTreeMap<String, crate::findings::ReviewedRefutationPrior>,
}

/// Optional deep-auditor tuning for bulk deep triage, read from the same
/// `maxSteps` / `depositUsd` / `temperature` options the single-finding deep
/// arm consumes; unset values keep the `DeepAuditConfig` defaults.
#[derive(Debug, Clone, Copy, Default)]
pub(in crate::modules) struct DeepTriageTuning {
    pub(in crate::modules) max_steps: Option<u32>,
    pub(in crate::modules) deposit_usd: Option<f64>,
    pub(in crate::modules) temperature: Option<f32>,
    pub(in crate::modules) taint_tools: crate::capabilities::deep_auditor::TaintToolPolicy,
}

fn parse_deep_triage_tuning(input: &Value) -> Result<DeepTriageTuning> {
    Ok(DeepTriageTuning {
        max_steps: input
            .get("maxSteps")
            .and_then(Value::as_u64)
            .map(|value| u32::try_from(value).unwrap_or(u32::MAX)),
        deposit_usd: input.get("depositUsd").and_then(Value::as_f64),
        temperature: input
            .get("temperature")
            .and_then(Value::as_f64)
            .map(|value| value.clamp(0.0, 2.0) as f32),
        taint_tools: parse_triage_taint_tools(input)?,
    })
}

fn parse_triage_taint_tools(
    input: &Value,
) -> Result<crate::capabilities::deep_auditor::TaintToolPolicy> {
    match input.get("taintTools").and_then(Value::as_str) {
        Some(value) => crate::capabilities::deep_auditor::TaintToolPolicy::parse(value),
        None => Ok(crate::capabilities::deep_auditor::TaintToolPolicy::default()),
    }
}

impl TriageRunInput {
    pub(in crate::modules) fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        let scan_id = parse_triage_scan_id(input)?;
        let fingerprints = parse_triage_fingerprints(input)?;
        let scope = if scan_id.is_some() {
            TriageScope::Latest
        } else {
            parse_triage_scope(input)?
        };
        Ok(Self {
            deep: triage_deep_enabled(input, scope, fingerprints.is_none()),
            fingerprints,
            prompt_template: parse_triage_prompt_template(input, cwd)?,
            scan_id,
            scope,
            concurrency: parse_triage_concurrency(input)?,
            cost_cap_usd: parse_triage_cost_cap_usd(input)?,
            prefilter_threshold: parse_triage_prefilter_threshold(input),
            stage2_tier: parse_triage_stage2_tier(input)?,
            model: optional_nonempty_string(input, "model")?,
            retriage: parse_triage_retriage(input),
            identity_reconcile: parse_identity_reconcile(input)?,
            model_dedupe: parse_model_dedupe(input)?,
            votes: parse_triage_votes(input)?,
            deep_tuning: parse_deep_triage_tuning(input)?,
            suppression_feedback: std::collections::BTreeMap::new(),
            reviewed_refutation_priors: std::collections::BTreeMap::new(),
        })
    }
}

fn parse_identity_reconcile(input: &Value) -> Result<IdentityReconcilePolicy> {
    match input.get("identityReconcile").and_then(Value::as_str) {
        Some("auto") => Ok(IdentityReconcilePolicy::Auto),
        None | Some("off") => Ok(IdentityReconcilePolicy::Off),
        Some(value) => {
            anyhow::bail!("triage:run identityReconcile must be auto or off, got {value:?}")
        }
    }
}

fn parse_model_dedupe(input: &Value) -> Result<ModelDedupePolicy> {
    match input.get("modelDedupe").and_then(Value::as_str) {
        None | Some("off") => Ok(ModelDedupePolicy::Off),
        Some("manual") => Ok(ModelDedupePolicy::Manual),
        Some("auto") => Ok(ModelDedupePolicy::Auto),
        Some(value) => {
            anyhow::bail!("triage:run modelDedupe must be off, manual, or auto, got {value:?}")
        }
    }
}

pub(in crate::modules) fn parse_triage_scope(input: &Value) -> Result<TriageScope> {
    let Some(value) = input.get("scope") else {
        return Ok(TriageScope::All);
    };
    match value.as_str().map(str::trim) {
        Some("latest") => Ok(TriageScope::Latest),
        Some("all") | Some("") => Ok(TriageScope::All),
        _ => anyhow::bail!("triage:run scope must be \"latest\" or \"all\", got {value}"),
    }
}

/// Deep classification is opt-in for targeted/latest runs (`strategy=deep`)
/// and the default for unfiltered `scope=all` bulk runs. An explicit
/// `strategy=standard` keeps the cheap single-shot path.
fn triage_deep_enabled(input: &Value, scope: TriageScope, is_unfiltered: bool) -> bool {
    match input
        .get("strategy")
        .and_then(Value::as_str)
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("standard") | Some("gate-deep") => false,
        Some("deep") => true,
        _ => scope == TriageScope::All && is_unfiltered,
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
