use super::*;

impl TaintIrisNextInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        let mode = TaintIrisNextMode::from_input(input)?;
        let backend = taint_iris_next_backend(input)?;
        let languages = taint_iris_next_languages(input)?;
        let caps = taint_iris_next_caps(input)?;
        let cwe_focus = parse_taint_iris_next_cwe_focus(input);
        let discover_signals = read_bool_option(input, "discoverSignals")
            .or_else(|| read_bool_option(input, "discover_signals"))
            .unwrap_or(true);
        let target_subdir = taint_iris_next_target_subdir(input)?;
        let allow_deterministic_fallback = read_bool_option(input, "allowDeterministicFallback")
            .or_else(|| read_bool_option(input, "allow_deterministic_fallback"))
            .unwrap_or(false);
        let extra_catalog_entries = parse_extra_catalog_entries(input)?;
        let system_prompt = optional_taint_next_string(input, &["TAINT_IRIS_NEXT_PROMPT"])?
            .unwrap_or_else(taint_iris_next_system_prompt);
        Ok(Self {
            threat_model: crate::capabilities::threat_model::ThreatModelSelection::from_input(
                input,
            )?,
            mode,
            catalog_digest_ref: catalog_digest_ref(input)?,
            backend,
            languages,
            caps,
            max_budget_usd: positive_f64_input(
                input,
                &["maxBudgetUsd", "max_budget_usd"],
                "taint-iris-next:hunt maxBudgetUsd",
            )?,
            cwe_focus,
            discover_signals,
            target_subdir,
            allow_deterministic_fallback,
            system_prompt,
            extra_catalog_entries,
        })
    }
}

fn catalog_digest_ref(input: &Value) -> Result<Option<String>> {
    let reference = optional_taint_next_string(input, &["catalogDigestRef", "catalog_digest_ref"])?;
    if let Some(value) = reference.as_deref().filter(|value| *value != "static") {
        crate::identity::Blake3Hash::new(value.into())?;
    }
    Ok(reference)
}

fn taint_iris_next_target_subdir(input: &Value) -> Result<Option<String>> {
    let subdir = optional_taint_next_string(input, &["targetSubdir", "target_subdir"])?
        .filter(|value| !value.trim().is_empty());
    if subdir.as_deref().is_some_and(invalid_target_subdir) {
        anyhow::bail!(
            "taint-iris-next:hunt targetSubdir must not contain '..' traversal, got {:?}",
            subdir.unwrap()
        );
    }
    Ok(subdir)
}

/// The prepare boundary may hand this option back target-absolute
/// (workspace-read normalization); containment under --target is enforced
/// when the scan root resolves. Only traversal is rejected here.
fn invalid_target_subdir(subdir: &str) -> bool {
    subdir.split('/').any(|part| part == "..")
}

pub(in crate::capabilities::taint_iris_next) fn parse_taint_iris_next_cwe_focus(
    input: &Value,
) -> Vec<String> {
    let raw = input.get("cweFocus").or_else(|| input.get("cwe_focus"));
    let mut tokens = Vec::new();
    match raw {
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(value) = item.as_str() {
                    tokens.push(value.to_string());
                }
            }
        }
        Some(Value::String(value)) => {
            tokens.extend(
                value
                    .split(|ch: char| ch == ',' || ch == ' ' || ch == ';')
                    .map(str::to_string),
            );
        }
        _ => {}
    }

    tokens
        .into_iter()
        .filter_map(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            let upper = trimmed.to_ascii_uppercase();
            let stripped = upper.strip_prefix("CWE-").unwrap_or(&upper);
            stripped
                .parse::<u32>()
                .ok()
                .map(|number| format!("CWE-{number}"))
                .or_else(|| Some(format!("CWE-{stripped}")))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Parse the optional `extraCatalogEntries` input field into ranked
/// catalog entries. The threat-intel dispatcher uses this to thread
/// operator-authored catalog TOML through to the agent without having
/// to recompile when new CVE classes are added.
fn parse_extra_catalog_entries(input: &Value) -> Result<Vec<TaintIrisNextRankedCatalogEntry>> {
    let Some(raw) = input
        .get("extraCatalogEntries")
        .or_else(|| input.get("extra_catalog_entries"))
    else {
        return Ok(Vec::new());
    };
    let items = raw.as_array().context(
        "taint-iris-next:hunt `extraCatalogEntries` must be an array of catalog-entry objects",
    )?;
    items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            parse_one_extra_entry(item, idx).with_context(|| {
                format!("taint-iris-next:hunt extraCatalogEntries[{idx}] is invalid")
            })
        })
        .collect()
}

fn parse_one_extra_entry(item: &Value, idx: usize) -> Result<TaintIrisNextRankedCatalogEntry> {
    let cwe = item
        .get("cwe")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .with_context(|| format!("extraCatalogEntries[{idx}].cwe is required"))?
        .to_string();
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("operator-supplied {cwe}"));
    let taint_class = item
        .get("taintClass")
        .or_else(|| item.get("taint_class"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "operator-supplied".to_string());
    let languages = read_string_array(item, &["languages"])?;
    let source_signals = read_string_array(item, &["sourceSignals", "source_signals"])?;
    let sink_signals = read_string_array(item, &["sinkSignals", "sink_signals"])?;
    let sanitizer_signals = read_string_array(item, &["sanitizerSignals", "sanitizer_signals"])?;
    let structural_queries = read_string_array(item, &["structuralQueries", "structural_queries"])?;
    let regex_markers = parse_regex_markers(item)?;

    // Operator-supplied entries score above all const-catalog entries.
    // If the operator went to the trouble of authoring a catalog entry
    // (or harvested one from a real CVE), they want it ranked highly
    // enough to survive the `max_catalog_entries` truncation. The 200
    // band sits above the 100-cap a built-in entry hits via
    // "threat-model CWE" match — see `rank_taint_iris_next_catalog`.
    let score = 200;
    let reasons = vec!["operator-supplied catalog entry (threat-intel)".to_string()];

    Ok(TaintIrisNextRankedCatalogEntry {
        cwe,
        name,
        taint_class,
        languages,
        source_signals,
        sink_signals,
        sanitizer_signals,
        structural_queries,
        regex_markers,
        score,
        reasons,
    })
}

fn parse_regex_markers(item: &Value) -> Result<Vec<TaintIrisNextRegexMarker>> {
    let Some(raw) = item
        .get("regexMarkers")
        .or_else(|| item.get("regex_markers"))
    else {
        return Ok(Vec::new());
    };
    let markers = raw
        .as_array()
        .context("regexMarkers must be an array of marker objects")?;
    markers
        .iter()
        .enumerate()
        .map(|(idx, marker)| parse_regex_marker(marker, idx))
        .collect()
}

fn parse_regex_marker(marker: &Value, idx: usize) -> Result<TaintIrisNextRegexMarker> {
    let pattern = marker
        .get("pattern")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("regexMarkers[{idx}].pattern is required"))?
        .to_string();
    let kind = marker
        .get("kind")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "source".to_string());
    let languages = read_string_array(marker, &["languages"])?;
    let marker_name = marker
        .get("marker")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("operator.regex.{idx}"));
    Ok(TaintIrisNextRegexMarker {
        pattern,
        kind,
        languages,
        marker: marker_name,
    })
}

fn read_string_array(item: &Value, keys: &[&str]) -> Result<Vec<String>> {
    for key in keys {
        if let Some(value) = item.get(*key) {
            return parse_string_array(value, key);
        }
    }
    Ok(Vec::new())
}

fn parse_string_array(value: &Value, label: &str) -> Result<Vec<String>> {
    let items = value
        .as_array()
        .with_context(|| format!("{label} must be an array of strings"))?;
    items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            item.as_str()
                .map(str::to_string)
                .with_context(|| format!("{label}[{idx}] must be a string"))
        })
        .collect()
}

fn taint_iris_next_backend(input: &Value) -> Result<String> {
    let backend =
        optional_taint_next_string(input, &["backend"])?.unwrap_or_else(|| "auto".to_string());
    if !matches!(
        backend.as_str(),
        "auto" | "structural" | "cpg-rs" | "cpg" | "semgrep" | "codeql" | "joern" | "language"
    ) {
        anyhow::bail!(
            "taint-iris-next:hunt backend must be auto, structural, cpg-rs, codeql, semgrep, or language (joern is a retired alias for cpg-rs)"
        );
    }
    Ok(backend)
}

fn taint_iris_next_languages(input: &Value) -> Result<Vec<String>> {
    Ok(string_list_input(input, &["languages"])?
        .unwrap_or_default()
        .into_iter()
        .map(|language| normalize_taint_next_language(&language))
        .filter(|language| !language.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>())
}

const CATALOG_ENTRY_KEYS: &[&str] = &[
    "maxCatalogEntries",
    "maxCwes",
    "max_catalog_entries",
    "max_cwes",
];
const CANDIDATES_PER_CWE_KEYS: &[&str] = &["maxCandidatesPerCwe", "max_candidates_per_cwe"];
const EVIDENCE_PER_CWE_KEYS: &[&str] = &["maxEvidencePerCwe", "max_evidence_per_cwe"];
const FILES_PER_QUERY_KEYS: &[&str] = &["maxFilesPerQuery", "max_files_per_query"];
const SPECS_PER_CWE_KEYS: &[&str] = &["maxSpecsPerCwe", "max_specs_per_cwe"];
const AGENT_FINDINGS_KEYS: &[&str] = &[
    "maxAgentFindings",
    "max_agent_findings",
    "maxFindings",
    "max_findings",
];
const CPG_SOURCE_FILES_KEYS: &[&str] = &["maxCpgSourceFiles", "max_cpg_source_files"];
const CODEQL_TIMEOUT_KEYS: &[&str] = &["codeqlAnalyzeTimeoutMs", "codeql_analyze_timeout_ms"];

fn taint_iris_next_caps(input: &Value) -> Result<TaintIrisNextCaps> {
    let cap = |keys: &[&str], label: &str, default: usize, ceiling: usize| {
        capped_usize_input(input, keys, label, default, ceiling)
    };
    Ok(TaintIrisNextCaps {
        max_catalog_entries: cap(CATALOG_ENTRY_KEYS, "maxCatalogEntries", 24, 100)?,
        max_candidates_per_cwe: cap(CANDIDATES_PER_CWE_KEYS, "maxCandidatesPerCwe", 2000, 10000)?,
        max_evidence_per_cwe: cap(EVIDENCE_PER_CWE_KEYS, "maxEvidencePerCwe", 12, 200)?,
        max_files_per_query: cap(FILES_PER_QUERY_KEYS, "maxFilesPerQuery", 120, 500)?,
        max_specs_per_cwe: cap(SPECS_PER_CWE_KEYS, "maxSpecsPerCwe", 16, 200)?,
        max_agent_findings: cap(AGENT_FINDINGS_KEYS, "maxAgentFindings", 20, 250)?,
        max_cpg_source_files: cap(
            CPG_SOURCE_FILES_KEYS,
            "maxCpgSourceFiles",
            kuzushi_cpg::DEFAULT_MAX_SOURCE_FILES,
            2_000_000,
        )?,
        codeql_analyze_timeout_ms: cap(
            CODEQL_TIMEOUT_KEYS,
            "codeqlAnalyzeTimeoutMs",
            180_000,
            900_000,
        )?
        .max(30_000),
        min_evidence_level: taint_iris_next_min_evidence_level(input)?,
    })
}

/// Parse one optional cap: `default` when absent, positive, and bounded by
/// `ceiling`. Labels render as `taint-iris-next:hunt <label>` in errors.
fn capped_usize_input(
    input: &Value,
    keys: &[&str],
    label: &str,
    default: usize,
    ceiling: usize,
) -> Result<usize> {
    let label = format!("taint-iris-next:hunt {label}");
    Ok(positive_usize_input(input, keys, &label)?
        .unwrap_or(default)
        .min(ceiling))
}

fn taint_iris_next_min_evidence_level(input: &Value) -> Result<String> {
    let min_evidence_level =
        optional_taint_next_string(input, &["minEvidenceLevel", "min_evidence_level"])?
            .unwrap_or_else(|| "linked".to_string());
    if !matches!(min_evidence_level.as_str(), "path" | "linked" | "candidate") {
        anyhow::bail!(
            "taint-iris-next:hunt minEvidenceLevel must be \"path\", \"linked\", or \"candidate\""
        );
    }
    Ok(min_evidence_level)
}

pub(in crate::capabilities::taint_iris_next) fn resolve_tool_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        return resolve_input_target(target, ctx);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    anyhow::bail!("taint-iris-next requires an explicit active workspace")
}

fn resolve_input_target(target: &str, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        anyhow::bail!("taint-iris-next target may not be blank")
    }
    resolve_candidate_target(PathBuf::from(trimmed), ctx)
}

fn resolve_candidate_target(candidate: PathBuf, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        let workspace = ctx
            .workspace
            .context("taint-iris-next requires an explicit active workspace")?;
        Ok(workspace.root().join(candidate))
    }
}

fn string_list_input(input: &Value, keys: &[&str]) -> Result<Option<Vec<String>>> {
    let Some(raw) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    match raw {
        Value::String(value) => Ok(Some(csv_string_values(value))),
        Value::Array(items) => string_array_values(items).map(Some),
        _ => anyhow::bail!("sast:scan list inputs must be a string or string array"),
    }
}

fn csv_string_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn string_array_values(items: &[Value]) -> Result<Vec<String>> {
    items.iter().map(nonempty_string_item).collect()
}

fn nonempty_string_item(item: &Value) -> Result<String> {
    item.as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .context("sast:scan list inputs must contain only non-empty strings")
}

pub(in crate::capabilities::taint_iris_next) fn read_bool_option(
    input: &Value,
    key: &str,
) -> Option<bool> {
    let raw = input.get(key)?;
    if let Some(value) = raw.as_bool() {
        return Some(value);
    }
    if let Some(value) = raw.as_str().and_then(parse_bool_text) {
        return Some(value);
    }
    raw.as_i64().map(|value| value != 0)
}

fn parse_bool_text(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub(in crate::capabilities::taint_iris_next) fn optional_nonempty_string(
    input: &Value,
    key: &str,
) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Some(_) => anyhow::bail!("triage:run {key} must be a string"),
        None => Ok(None),
    }
}

pub(in crate::capabilities::taint_iris_next) fn optional_taint_next_string(
    input: &Value,
    keys: &[&str],
) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return parse_optional_taint_next_string(value, key);
        }
    }
    Ok(None)
}

fn parse_optional_taint_next_string(value: &Value, key: &str) -> Result<Option<String>> {
    match value {
        Value::String(text) => Ok(Some(text.trim().to_string()).filter(|s| !s.is_empty())),
        _ => anyhow::bail!("taint-iris-next:hunt {key} must be a string"),
    }
}

fn positive_usize_input(input: &Value, keys: &[&str], label: &str) -> Result<Option<usize>> {
    keys.iter()
        .find_map(|key| input.get(*key))
        .map(|value| parse_positive_usize(value, label))
        .transpose()
}

fn parse_positive_usize(value: &Value, label: &str) -> Result<usize> {
    match value {
        Value::Number(number) => parse_positive_u64(number.as_u64(), label),
        Value::String(value) => parse_positive_usize_string(value, label),
        _ => anyhow::bail!("{label} must be a positive integer"),
    }
}

fn parse_positive_u64(value: Option<u64>, label: &str) -> Result<usize> {
    let parsed = value.with_context(|| format!("{label} must be a positive integer"))?;
    require_nonzero_usize(parsed as usize, label)
}

fn parse_positive_usize_string(value: &str, label: &str) -> Result<usize> {
    let parsed = value
        .trim()
        .parse::<usize>()
        .with_context(|| format!("{label} must be a positive integer"))?;
    require_nonzero_usize(parsed, label)
}

fn require_nonzero_usize(value: usize, label: &str) -> Result<usize> {
    if value == 0 {
        anyhow::bail!("{label} must be a positive integer");
    }
    Ok(value)
}

fn positive_f64_input(input: &Value, keys: &[&str], label: &str) -> Result<Option<f64>> {
    keys.iter()
        .find_map(|key| input.get(*key))
        .map(|value| parse_positive_f64(value, label))
        .transpose()
}

fn parse_positive_f64(value: &Value, label: &str) -> Result<f64> {
    let parsed = parse_f64_value(value, label)?;
    require_positive_f64(parsed, label)
}

fn parse_f64_value(value: &Value, label: &str) -> Result<f64> {
    if let Some(parsed) = value.as_f64() {
        return Ok(parsed);
    }
    parse_f64_string(
        value
            .as_str()
            .with_context(|| format!("{label} must be a positive number"))?,
        label,
    )
}

fn parse_f64_string(value: &str, label: &str) -> Result<f64> {
    value
        .trim()
        .parse::<f64>()
        .with_context(|| format!("{label} must be a positive number"))
}

fn require_positive_f64(value: f64, label: &str) -> Result<f64> {
    if !value.is_finite() || value <= 0.0 {
        anyhow::bail!("{label} must be a positive number");
    }
    Ok(value)
}
