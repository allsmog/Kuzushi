use super::prelude::*;
use super::*;

impl TaintIrisNextInput {
    pub(in crate::modules) fn from_tool_input(input: &Value) -> Result<Self> {
        let mode = TaintIrisNextMode::from_input(input)?;
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
        let languages = string_list_input(input, &["languages"])?
            .unwrap_or_default()
            .into_iter()
            .map(|language| normalize_taint_next_language(&language))
            .filter(|language| !language.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let min_evidence_level =
            optional_taint_next_string(input, &["minEvidenceLevel", "min_evidence_level"])?
                .unwrap_or_else(|| "linked".to_string());
        if !matches!(min_evidence_level.as_str(), "path" | "linked" | "candidate") {
            anyhow::bail!(
                "taint-iris-next:hunt minEvidenceLevel must be \"path\", \"linked\", or \"candidate\""
            );
        }
        let caps = TaintIrisNextCaps {
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
        };
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
        })
    }
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
