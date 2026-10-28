//! Project recorded requests without rereading rule files or mutable tool settings.
use crate::capabilities::campaign::FrozenContextCase;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// A report-only subset of the authenticated plan, not an enabled-rule inventory.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationScanSelection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    pub parameters: BTreeMap<String, Value>,
}

const RECORDED_PARAMETERS: [&str; 6] = [
    "taskMode",
    "tasks",
    "semgrepConfig",
    "semgrepBinary",
    "semgrepJobs",
    "semgrepTimeoutMs",
];

pub(super) fn single(input: &Value) -> Vec<InvestigationScanSelection> {
    let selection = from_input(None, input);
    if selection.parameters.is_empty() {
        return Vec::new();
    }
    vec![selection]
}

pub(super) fn cases(cases: &[FrozenContextCase]) -> Vec<InvestigationScanSelection> {
    cases
        .iter()
        .map(|case| from_input(Some(&case.id), &case.base_input))
        .collect()
}

fn from_input(case_id: Option<&str>, input: &Value) -> InvestigationScanSelection {
    let parameters = RECORDED_PARAMETERS
        .into_iter()
        .filter_map(|key| input.get(key).map(|value| (key.into(), value.clone())))
        .collect();
    InvestigationScanSelection {
        case_id: case_id.map(str::to_owned),
        parameters,
    }
}

#[cfg(test)]
mod tests;
