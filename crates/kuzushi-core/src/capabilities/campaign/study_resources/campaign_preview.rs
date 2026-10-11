//! Frozen historical observations, not future spending bounds.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Number;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseResourceEvidenceV1 {
    pub case_id: String,
    pub equivalence_sha256: String,
    pub passes: usize,
    pub run_ids: Vec<String>,
    pub calls_per_pass: Option<[u32; 2]>,
    pub cost_per_pass_usd: Option<[Number; 2]>,
    pub limitations: Vec<String>,
}

pub(in crate::capabilities::campaign) fn from_plan(
    plan: &serde_json::Value,
    cases: &[crate::capabilities::campaign::FrozenContextCase],
) -> Result<Option<StudyResourceEvidenceV1>> {
    let Some(value) = plan.get("resourceEvidence") else {
        return Ok(None);
    };
    let evidence: StudyResourceEvidenceV1 = serde_json::from_value(value.clone())?;
    evidence.project(1)?;
    anyhow::ensure!(
        evidence.cases.len() == cases.len(),
        "Resource evidence has different cases"
    );
    for (recorded, case) in evidence.cases.iter().zip(cases) {
        require_case_binding(recorded, case)?;
    }
    Ok(Some(evidence))
}

fn require_case_binding(
    recorded: &CaseResourceEvidenceV1,
    expected: &crate::capabilities::campaign::FrozenContextCase,
) -> Result<()> {
    anyhow::ensure!(
        (
            recorded.case_id.as_str(),
            recorded.passes,
            recorded.equivalence_sha256.as_str()
        ) == (
            expected.id.as_str(),
            expected.passes,
            expected.equivalence.sha256.as_str()
        ),
        "Resource evidence belongs to different frozen conditions"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StudyResourceEvidenceV1 {
    pub schema_version: u32,
    pub baseline_campaign_id: String,
    pub baseline_plan_sha256: String,
    pub cases: Vec<CaseResourceEvidenceV1>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResourceScenario {
    pub starts: u64,
    pub provider_calls: Option<[u64; 2]>,
    pub cost_usd: Option<[f64; 2]>,
    pub uncalibrated_cases: usize,
}

impl StudyResourceEvidenceV1 {
    pub fn project(&self, attempts: usize) -> Result<ResourceScenario> {
        anyhow::ensure!(
            self.schema_version == 1,
            "Unsupported study resource evidence"
        );
        anyhow::ensure!((1..=10).contains(&attempts), "Invalid projected attempts");
        anyhow::ensure!(
            !self.cases.is_empty() && self.cases.len() <= 9,
            "Invalid resource cases"
        );
        let jobs = self
            .cases
            .iter()
            .map(|case| case.passes)
            .try_fold(0usize, usize::checked_add)
            .context("Resource workload overflow")?;
        anyhow::ensure!(jobs <= 100, "Resource workload exceeds 100 fixed jobs");
        let mut result = ResourceScenario {
            starts: 0,
            provider_calls: Some([0, 0]),
            cost_usd: Some([0.0, 0.0]),
            uncalibrated_cases: 0,
        };
        for case in &self.cases {
            add_case(&mut result, case, attempts)?;
        }
        Ok(result)
    }
}

fn add_case(
    result: &mut ResourceScenario,
    case: &CaseResourceEvidenceV1,
    attempts: usize,
) -> Result<()> {
    anyhow::ensure!((1..=100).contains(&case.passes), "Invalid projected passes");
    let starts = (case.passes as u64) * (attempts as u64);
    result.starts = result
        .starts
        .checked_add(starts)
        .context("Resource workload overflow")?;
    anyhow::ensure!(
        result.starts <= 1000,
        "Resource workload exceeds fixed-job limits"
    );
    let calls = case
        .calls_per_pass
        .map(|range| range.map(|value| u64::from(value) * starts));
    result.provider_calls = add_calls(result.provider_calls, calls)?;
    result.cost_usd = add_cost(result.cost_usd, cost_range(case, starts));
    result.uncalibrated_cases += usize::from(case.calls_per_pass.is_none());
    Ok(())
}

fn add_calls(total: Option<[u64; 2]>, next: Option<[u64; 2]>) -> Result<Option<[u64; 2]>> {
    let Some((total, next)) = total.zip(next) else {
        return Ok(None);
    };
    anyhow::ensure!(next[0] <= next[1], "Invalid historical request range");
    Ok(Some([
        total[0]
            .checked_add(next[0])
            .context("Request projection overflow")?,
        total[1]
            .checked_add(next[1])
            .context("Request projection overflow")?,
    ]))
}

fn cost_range(case: &CaseResourceEvidenceV1, starts: u64) -> Option<[f64; 2]> {
    let range = case.cost_per_pass_usd.as_ref()?;
    let values = [
        range[0].as_f64()? * starts as f64,
        range[1].as_f64()? * starts as f64,
    ];
    (values
        .iter()
        .all(|value| value.is_finite() && *value >= 0.0)
        && values[0] <= values[1])
        .then_some(values)
}

fn add_cost(total: Option<[f64; 2]>, next: Option<[f64; 2]>) -> Option<[f64; 2]> {
    let (total, next) = total.zip(next)?;
    let sum = [total[0] + next[0], total[1] + next[1]];
    sum.iter().all(|value| value.is_finite()).then_some(sum)
}

#[cfg(test)]
mod tests;
