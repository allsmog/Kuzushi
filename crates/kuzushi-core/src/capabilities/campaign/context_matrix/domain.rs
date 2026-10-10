//! Finite context cases. Validation has no filesystem or runtime effects.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const MAX_CONTEXT_CASES: usize = 8;
pub const MAX_MATRIX_JOBS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextCaseInput {
    pub id: String,
    pub label: String,
    pub threat_model_ref: Value,
    #[serde(default = "default_case_passes")]
    pub passes: usize,
}

fn default_case_passes() -> usize {
    3
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextMatrixDraft {
    pub baseline_case_id: String,
    pub cases: Vec<ContextCaseInput>,
}

impl ContextMatrixDraft {
    pub fn from_input(input: &Value) -> Result<Option<Self>> {
        let Some(cases) = input.get("contextCases") else {
            anyhow::ensure!(
                input.get("baselineCaseId").is_none(),
                "baselineCaseId requires contextCases"
            );
            return Ok(None);
        };
        anyhow::ensure!(
            input.get("contextBaselineRunId").is_none(),
            "Choose a fresh matrix baseline or one historical baseline comparison, not both"
        );
        let draft = Self {
            baseline_case_id: input["baselineCaseId"]
                .as_str()
                .context("A context matrix requires an explicit baselineCaseId")?
                .into(),
            cases: serde_json::from_value(cases_with_default_passes(cases, input)?)
                .context("Invalid contextCases")?,
        };
        draft.validate()?;
        Ok(Some(draft))
    }

    pub fn job_count(&self) -> usize {
        self.cases
            .iter()
            .fold(0usize, |count, case| count.saturating_add(case.passes))
    }

    pub fn baseline(&self) -> Result<&ContextCaseInput> {
        self.cases
            .iter()
            .find(|case| case.id == self.baseline_case_id)
            .context("Context matrix baseline is missing")
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (2..=MAX_CONTEXT_CASES).contains(&self.cases.len()),
            "A context matrix needs two to eight explicit cases"
        );
        let mut ids = BTreeSet::new();
        let mut references = BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            anyhow::ensure!(ids.insert(&case.id), "Context case ids must be unique");
            anyhow::ensure!(references.insert(crate::review_yield::domain::canonical_json_bytes(&case.threat_model_ref)?), "Context cases must use different exact revisions; use repetitions for identical context");
        }
        anyhow::ensure!(
            ids.contains(&self.baseline_case_id),
            "The selected baseline case is outside this matrix"
        );
        anyhow::ensure!(
            self.job_count() <= MAX_MATRIX_JOBS,
            "Context matrix exceeds 100 fixed scan jobs"
        );
        Ok(())
    }
}

fn cases_with_default_passes(cases: &Value, input: &Value) -> Result<Value> {
    let mut cases = cases
        .as_array()
        .context("contextCases must be an array")?
        .clone();
    anyhow::ensure!(
        (2..=MAX_CONTEXT_CASES).contains(&cases.len()),
        "A context matrix needs two to eight explicit cases"
    );
    let passes = input
        .get("trials")
        .cloned()
        .unwrap_or_else(|| Value::from(3));
    for case in &mut cases {
        case.as_object_mut()
            .context("Context case must be an object")?
            .entry("passes")
            .or_insert_with(|| passes.clone());
    }
    Ok(Value::Array(cases))
}

impl ContextCaseInput {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (1..=40).contains(&self.id.len()),
            "Context case id needs 1 to 40 characters"
        );
        anyhow::ensure!(
            self.id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "Context case id accepts letters, numbers, hyphens and underscores"
        );
        anyhow::ensure!(
            !self.label.trim().is_empty() && self.label.len() <= 256,
            "Context case label needs 1 to 256 bytes"
        );
        anyhow::ensure!(
            !self.label.chars().any(char::is_control),
            "Context case label cannot contain control characters"
        );
        anyhow::ensure!(
            (1..=MAX_MATRIX_JOBS).contains(&self.passes),
            "Case repetitions must be between 1 and 100"
        );
        validate_context_reference(&self.threat_model_ref)
    }
}

fn validate_context_reference(value: &Value) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    let reference: crate::capabilities::threat_model::ThreatModelRef =
        serde_json::from_value(value.clone())
            .context("Context case needs an exact threatModelRef or explicit null omission")?;
    crate::capabilities::threat_model::ThreatModelId::parse(reference.model_id.as_str())?;
    crate::capabilities::threat_model::ThreatModelRevisionId::parse(
        reference.revision_id.as_str(),
    )?;
    let digest = reference
        .sha256
        .strip_prefix("sha256:")
        .context("Context reference needs a sha256 digest")?;
    anyhow::ensure!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Context reference digest is incomplete"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
