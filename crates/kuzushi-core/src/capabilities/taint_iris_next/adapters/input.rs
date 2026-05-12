use super::*;

impl TaintIrisNextInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        let mode = TaintIrisNextMode::from_input(input)?;
        let backend = taint_iris_next_backend(input)?;
        let languages = taint_iris_next_languages(input)?;
        let caps = taint_iris_next_caps(input)?;
        let allow_deterministic_fallback = read_bool_option(input, "allowDeterministicFallback")
            .or_else(|| read_bool_option(input, "allow_deterministic_fallback"))
            .unwrap_or(false);
        let extra_catalog_entries = parse_extra_catalog_entries(input)?;
        Ok(Self {
            mode,
            backend,
            languages,
            caps,
            max_budget_usd: positive_f64_input(
                input,
                &["maxBudgetUsd", "max_budget_usd"],
                "taint-iris-next:hunt maxBudgetUsd",
            )?,
            allow_deterministic_fallback,
            extra_catalog_entries,
        })
    }
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
        score,
        reasons,
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
        "auto" | "structural" | "semgrep" | "codeql" | "joern" | "language"
    ) {
        anyhow::bail!(
            "taint-iris-next:hunt backend must be auto, structural, semgrep, codeql, joern, or language"
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

fn taint_iris_next_caps(input: &Value) -> Result<TaintIrisNextCaps> {
    let min_evidence_level = taint_iris_next_min_evidence_level(input)?;
    Ok(TaintIrisNextCaps {
        max_catalog_entries: positive_usize_input(
            input,
            &[
                "maxCatalogEntries",
                "maxCwes",
                "max_catalog_entries",
                "max_cwes",
            ],
            "taint-iris-next:hunt maxCatalogEntries",
        )?
        .unwrap_or(24)
        .min(100),
        max_candidates_per_cwe: positive_usize_input(
            input,
            &["maxCandidatesPerCwe", "max_candidates_per_cwe"],
            "taint-iris-next:hunt maxCandidatesPerCwe",
        )?
        .unwrap_or(24)
        .min(200),
        max_evidence_per_cwe: positive_usize_input(
            input,
            &["maxEvidencePerCwe", "max_evidence_per_cwe"],
            "taint-iris-next:hunt maxEvidencePerCwe",
        )?
        .unwrap_or(12)
        .min(200),
        max_files_per_query: positive_usize_input(
            input,
            &["maxFilesPerQuery", "max_files_per_query"],
            "taint-iris-next:hunt maxFilesPerQuery",
        )?
        .unwrap_or(25)
        .min(500),
        max_specs_per_cwe: positive_usize_input(
            input,
            &["maxSpecsPerCwe", "max_specs_per_cwe"],
            "taint-iris-next:hunt maxSpecsPerCwe",
        )?
        .unwrap_or(16)
        .min(200),
        max_agent_findings: positive_usize_input(
            input,
            &[
                "maxAgentFindings",
                "max_agent_findings",
                "maxFindings",
                "max_findings",
            ],
            "taint-iris-next:hunt maxAgentFindings",
        )?
        .unwrap_or(20)
        .min(250),
        codeql_analyze_timeout_ms: positive_usize_input(
            input,
            &["codeqlAnalyzeTimeoutMs", "codeql_analyze_timeout_ms"],
            "taint-iris-next:hunt codeqlAnalyzeTimeoutMs",
        )?
        .unwrap_or(180_000)
        .clamp(30_000, 900_000),
        min_evidence_level,
    })
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
        return resolve_input_target(target);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    current_dir()
}

fn resolve_input_target(target: &str) -> Result<PathBuf> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return current_dir();
    }
    resolve_candidate_target(PathBuf::from(trimmed))
}

fn resolve_candidate_target(candidate: PathBuf) -> Result<PathBuf> {
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        Ok(current_dir()?.join(candidate))
    }
}

fn current_dir() -> Result<PathBuf> {
    std::env::current_dir().context("Could not resolve current directory")
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

fn optional_taint_next_string(input: &Value, keys: &[&str]) -> Result<Option<String>> {
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
