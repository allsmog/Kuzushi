use super::*;

impl TaintIrisNextInput {
    pub(in crate::modules) fn from_tool_input(input: &Value) -> Result<Self> {
        let mode = TaintIrisNextMode::from_input(input)?;
        let backend = taint_iris_next_backend(input)?;
        let languages = taint_iris_next_languages(input)?;
        let caps = taint_iris_next_caps(input)?;
        let cwe_focus = parse_taint_iris_next_cwe_focus(input);
        // Default ON. The operator opts out via either a JSON-bool
        // false on `discoverSignals` (the camelCase shell option) or
        // its snake-case alias. Loose parsing matches the rest of the
        // module's option helpers — read_bool_option accepts
        // true/false/1/0/yes/no/on/off.
        let discover_signals = read_bool_option(input, "discoverSignals")
            .or_else(|| read_bool_option(input, "discover_signals"))
            .unwrap_or(true);
        // Default OFF. Per CLAUDE.md §"Model & runtime safety", we
        // never silently project linked stories as findings when the
        // agent fails. Operators who want that legacy behaviour opt
        // in via `set taint-iris-next:hunt allowDeterministicFallback
        // true` (UI / shell option) or
        // `KUZUSHI_TAINT_IRIS_NEXT_ALLOW_DETERMINISTIC_FALLBACK=1`
        // (env var, useful for CI scripts where the option-store
        // isn't around).
        let allow_deterministic_fallback = read_bool_option(input, "allowDeterministicFallback")
            .or_else(|| read_bool_option(input, "allow_deterministic_fallback"))
            .or_else(|| {
                std::env::var("KUZUSHI_TAINT_IRIS_NEXT_ALLOW_DETERMINISTIC_FALLBACK")
                    .ok()
                    .and_then(|raw| match raw.trim().to_lowercase().as_str() {
                        "true" | "1" | "yes" | "on" => Some(true),
                        "false" | "0" | "no" | "off" => Some(false),
                        _ => None,
                    })
            })
            .unwrap_or(false);
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
            cwe_focus,
            discover_signals,
            allow_deterministic_fallback,
        })
    }
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

#[derive(Debug, Clone, Copy)]
pub(in crate::modules) struct TaintIrisNextCatalogEntry {
    pub(in crate::modules) cwe: &'static str,
    pub(in crate::modules) name: &'static str,
    pub(in crate::modules) taint_class: &'static str,
    pub(in crate::modules) languages: &'static [&'static str],
    pub(in crate::modules) source_signals: &'static [&'static str],
    pub(in crate::modules) sink_signals: &'static [&'static str],
    pub(in crate::modules) sanitizer_signals: &'static [&'static str],
    pub(in crate::modules) structural_queries: &'static [&'static str],
}
