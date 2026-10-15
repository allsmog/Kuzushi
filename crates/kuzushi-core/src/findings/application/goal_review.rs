//! A brief-bound view of priorities over the unchanged authoritative findings.
use crate::capabilities::campaign::BriefRevision;
use crate::findings::{
    Finding, FindingGoalAssessment, FindingGoalBasis, FindingStore, GoalRelevance,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingGoalRow {
    pub finding: Finding,
    pub basis: FindingGoalBasis,
    pub assessment: Option<FindingGoalAssessment>,
    pub matches_observation: bool,
    #[serde(default)]
    pub source_git: Option<crate::RunTargetGitMetadata>,
}

impl FindingGoalRow {
    pub fn relevance(&self) -> Option<GoalRelevance> {
        self.assessment
            .as_ref()
            .filter(|_| self.matches_observation)
            .map(|record| record.relevance)
            .filter(|value| *value != GoalRelevance::Cleared)
    }

    pub fn label(&self) -> &'static str {
        if self.assessment.is_some() && !self.matches_observation {
            return "Observation changed";
        }
        self.relevance().map_or("Unassessed", GoalRelevance::label)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingGoalPage {
    pub schema_version: u32,
    pub brief: Option<BriefRevision>,
    pub rows: Vec<FindingGoalRow>,
    pub total: usize,
    pub offset: usize,
    pub has_more: bool,
    pub watermark: u64,
}

pub(crate) fn read_goals(
    store: &FindingStore,
    brief: Option<BriefRevision>,
    offset: usize,
    limit: usize,
    filter: &str,
    canceled: &dyn Fn() -> bool,
) -> Result<FindingGoalPage> {
    anyhow::ensure!(
        (1..=200).contains(&limit) && offset <= 1_000_000,
        "Invalid goal review page"
    );
    validate_filter(filter)?;
    store.with_projection_snapshot(|store| {
        let watermark = store.projection_meta()?.applied_seq;
        let rows = goal_rows(store, brief.as_ref(), filter, canceled)?;
        let total = rows.len();
        let rows = rows
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();
        Ok(FindingGoalPage {
            schema_version: 1,
            brief,
            has_more: offset.saturating_add(rows.len()) < total,
            rows,
            total,
            offset,
            watermark,
        })
    })
}

fn goal_rows(
    store: &FindingStore,
    brief: Option<&BriefRevision>,
    filter: &str,
    canceled: &dyn Fn() -> bool,
) -> Result<Vec<FindingGoalRow>> {
    let Some(brief) = brief else {
        return Ok(Vec::new());
    };
    let mut assessments = store
        .goals_for_brief(&brief.reference)?
        .into_iter()
        .map(|row| (row.basis.finding_id, row))
        .collect::<BTreeMap<_, _>>();
    let mut rows = Vec::new();
    let findings = store.list_all_findings()?;
    let mut bases = store.goal_bases(&findings)?;
    for finding in findings {
        anyhow::ensure!(!canceled(), "Goal review read canceled");
        let id = finding.id.context("Goal review finding id is missing")?;
        let basis = bases
            .remove(&id)
            .context("Goal observation basis is missing")?;
        let assessment = assessments.remove(&id);
        let matches_observation = assessment.as_ref().is_some_and(|row| row.basis == basis);
        let row = FindingGoalRow {
            finding,
            basis,
            assessment,
            matches_observation,
            source_git: None,
        };
        if matches_filter(&row, filter) {
            rows.push(row);
        }
    }
    rows.sort_by_key(|row| row.relevance().map_or(2, GoalRelevance::order));
    Ok(rows)
}

fn validate_filter(filter: &str) -> Result<()> {
    anyhow::ensure!(
        matches!(
            filter,
            "all" | "unassessed" | "direct" | "related" | "outside" | "uncertain"
        ),
        "Unsupported goal review filter"
    );
    Ok(())
}

fn matches_filter(row: &FindingGoalRow, filter: &str) -> bool {
    if filter == "all" {
        return true;
    }
    if filter == "unassessed" {
        return row.relevance().is_none();
    }
    row.relevance()
        .is_some_and(|value| value.as_str() == filter)
}
