use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::modules) enum TaintIrisNextMode {
    Plan,
    Hunt,
}

impl TaintIrisNextMode {
    pub(in crate::modules) fn from_input(input: &Value) -> Result<Self> {
        match input.get("mode").and_then(Value::as_str).unwrap_or("plan") {
            "plan" => Ok(Self::Plan),
            "hunt" => Ok(Self::Hunt),
            other => anyhow::bail!(
                "taint-iris-next:hunt mode must be \"plan\" or \"hunt\", got {other:?}"
            ),
        }
    }

    pub(in crate::modules) fn as_str(&self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Hunt => "hunt",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextCaps {
    pub(in crate::modules) max_catalog_entries: usize,
    pub(in crate::modules) max_candidates_per_cwe: usize,
    pub(in crate::modules) max_evidence_per_cwe: usize,
    pub(in crate::modules) max_files_per_query: usize,
    pub(in crate::modules) max_specs_per_cwe: usize,
    pub(in crate::modules) max_agent_findings: usize,
    pub(in crate::modules) codeql_analyze_timeout_ms: usize,
    pub(in crate::modules) min_evidence_level: String,
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct TaintIrisNextInput {
    pub(in crate::modules) mode: TaintIrisNextMode,
    pub(in crate::modules) backend: String,
    pub(in crate::modules) languages: Vec<String>,
    pub(in crate::modules) caps: TaintIrisNextCaps,
    pub(in crate::modules) max_budget_usd: Option<f64>,
    /// Operator-supplied CWE allow-list. When non-empty, both the
    /// ranked catalog (and therefore the structural seeds) and the
    /// agent prompt are scoped to these CWEs only. Read from the
    /// `cweFocus` shell option; identifiers are normalised to upper
    /// case and prefixed with "CWE-" so `78`, `cwe-78`, and `CWE-78`
    /// all match the same catalog entry.
    pub(in crate::modules) cwe_focus: Vec<String>,
}

/// Parse a JSON value (string, array of strings, or comma/space
/// separated string) into a normalised CWE allow-list. Empty input
/// returns an empty vec; the caller treats that as "no filter".
pub(in crate::modules) fn parse_taint_iris_next_cwe_focus(input: &Value) -> Vec<String> {
    let raw = input.get("cweFocus").or_else(|| input.get("cwe_focus"));
    let mut tokens: Vec<String> = Vec::new();
    match raw {
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    tokens.push(s.to_string());
                }
            }
        }
        Some(Value::String(s)) => {
            tokens.extend(
                s.split(|c: char| c == ',' || c == ' ' || c == ';')
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
            let stripped = upper
                .strip_prefix("CWE-")
                .map(str::to_string)
                .unwrap_or(upper);
            stripped
                .parse::<u32>()
                .ok()
                .map(|n| format!("CWE-{n}"))
                .or(Some(format!("CWE-{stripped}")))
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}
