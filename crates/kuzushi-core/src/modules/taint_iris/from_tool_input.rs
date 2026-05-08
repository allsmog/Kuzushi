use super::*;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintCweSelection {
    pub(in crate::modules) id: String,
    pub(in crate::modules) name: String,
    pub(in crate::modules) reason: String,
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct TaintIrisInput {
    pub(in crate::modules) max_cwes: Option<usize>,
    pub(in crate::modules) max_findings: usize,
    pub(in crate::modules) prompt_override: Option<String>,
    pub(in crate::modules) max_budget_usd: Option<f64>,
}

impl TaintIrisInput {
    pub(in crate::modules) fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        let prompt_override = optional_nonempty_string(input, "TAINT_IRIS_PROMPT")?
            .map(|value| resolve_prompt_override_for_key(&value, cwd, "TAINT_IRIS_PROMPT"))
            .transpose()?;
        Ok(Self {
            max_cwes: positive_usize_input(
                input,
                &["maxCwes", "max_cwes"],
                "taint-iris:hunt maxCwes",
            )?,
            max_findings: positive_usize_input(
                input,
                &["maxFindings", "max_findings"],
                "taint-iris:hunt maxFindings",
            )?
            .unwrap_or(50)
            .min(250),
            prompt_override,
            max_budget_usd: positive_f64_input(
                input,
                &["maxBudgetUsd", "max_budget_usd"],
                "taint-iris:hunt maxBudgetUsd",
            )?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisReport {
    pub(in crate::modules) target: String,
    pub(in crate::modules) count: usize,
    pub(in crate::modules) cwes: Vec<TaintCweSelection>,
    pub(in crate::modules) findings: Vec<Finding>,
    pub(in crate::modules) persisted: Option<TaintIrisPersistedRun>,
    pub(in crate::modules) cost_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::modules) degradation: Option<Value>,
}
