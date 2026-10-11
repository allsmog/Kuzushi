//! Pure selection of bounded scope cases; acceptance is checked by planning.
use super::*;
use std::collections::BTreeSet;

const MAX_SCOPE_CASES: usize = 9;
const MAX_SCOPE_JOBS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeStudyCaseInput {
    pub scope_id: String,
    pub passes: usize,
    #[serde(
        default,
        deserialize_with = "explicit_context",
        skip_serializing_if = "Option::is_none"
    )]
    pub threat_model_ref: Option<Value>,
}

fn explicit_context<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeStudyDraft {
    pub proposal_ref: ScanScopeProposalRef,
    pub cases: Vec<ScopeStudyCaseInput>,
}

impl ScopeStudyDraft {
    pub fn from_input(input: &Value) -> Result<Option<Self>> {
        let Some(cases) = input.get("scopeCases") else {
            anyhow::ensure!(
                input.get("scopeProposalRef").is_none(),
                "scopeProposalRef requires scopeCases"
            );
            return Ok(None);
        };
        require_scope_study_options(input)?;
        let draft = Self {
            proposal_ref: serde_json::from_value(input["scopeProposalRef"].clone())
                .context("Scope study requires an exact scopeProposalRef")?,
            cases: serde_json::from_value(default_passes(cases, input)?)?,
        };
        draft.validate()?;
        Ok(Some(draft))
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (1..=MAX_SCOPE_CASES).contains(&self.cases.len()),
            "Scope study requires one to nine selected discovery scopes"
        );
        let mut ids = BTreeSet::new();
        for case in &self.cases {
            validate_case(case)?;
            anyhow::ensure!(
                ids.insert(&case.scope_id),
                "Scope study cannot repeat a boundary; use its passes"
            );
        }
        anyhow::ensure!(
            self.job_count() <= MAX_SCOPE_JOBS,
            "Scope study exceeds 100 fixed jobs; reduce the selected workload"
        );
        Ok(())
    }

    pub fn job_count(&self) -> usize {
        self.cases
            .iter()
            .fold(0usize, |total, case| total.saturating_add(case.passes))
    }
}

fn require_scope_study_options(input: &Value) -> Result<()> {
    for key in [
        "contextCases",
        "baselineCaseId",
        "contextBaselineRunId",
        "baselineRunId",
    ] {
        anyhow::ensure!(
            input.get(key).is_none(),
            "{key} cannot be mixed into a scope study; approve a separate context or usage study"
        );
    }
    anyhow::ensure!(
        input["scanInput"].get("scanScopeRef").is_none(),
        "Selected scope bindings belong in scopeCases, not scanInput.scanScopeRef"
    );
    Ok(())
}

fn default_passes(cases: &Value, input: &Value) -> Result<Value> {
    let cases = cases.as_array().context("scopeCases must be an array")?;
    anyhow::ensure!(
        (1..=MAX_SCOPE_CASES).contains(&cases.len()),
        "Scope study requires one to nine selected scopes"
    );
    let mut cases = cases.clone();
    for case in &mut cases {
        case.as_object_mut()
            .context("Scope case must be an object")?
            .entry("passes")
            .or_insert_with(|| input.get("trials").cloned().unwrap_or(json!(3)));
    }
    Ok(Value::Array(cases))
}

fn validate_case(case: &ScopeStudyCaseInput) -> Result<()> {
    anyhow::ensure!(
        (1..=64).contains(&case.scope_id.len())
            && case
                .scope_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "Invalid selected scope id"
    );
    anyhow::ensure!(
        (1..=MAX_SCOPE_JOBS).contains(&case.passes),
        "Scope passes must be between 1 and 100"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
