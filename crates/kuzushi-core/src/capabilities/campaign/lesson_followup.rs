//! Read an authenticated lesson context and retain its investigation accounting.
use crate::allowance::AllowanceSnapshot;
use crate::capabilities::threat_model::{ThreatModelRef, ThreatModelSelection};
use crate::findings::FindingLesson;
use anyhow::{Context, Result};
use std::{collections::BTreeSet, path::Path};

#[derive(Debug, Clone, PartialEq)]
pub struct LessonFollowupContext {
    pub lesson_count: usize,
    pub source_run_ids: Vec<String>,
    pub unaccounted_source_runs: usize,
    pub allowance: Option<AllowanceSnapshot>,
}

/// This reads existing records only. It creates no plan or spending permission.
pub fn load_lesson_followup_context(
    root: &Path,
    reference: &ThreatModelRef,
    preferred_investigation: Option<&str>,
) -> Result<LessonFollowupContext> {
    let selection = ThreatModelSelection::Revision(reference.clone());
    let document = crate::capabilities::threat_model::load_selected_threat_model(root, &selection)?
        .context("Saved lesson context is unavailable")?;
    let records: Vec<FindingLesson> =
        serde_json::from_value(document["reviewedLessons"].clone())
            .context("Create a context copy with accepted lessons before planning a follow-up")?;
    anyhow::ensure!(
        (1..=8).contains(&records.len()),
        "Select one to eight accepted lessons for this follow-up"
    );
    let runs = records
        .iter()
        .filter_map(|record| record.origin.finding.run_id.clone())
        .collect::<BTreeSet<_>>();
    let missing = records
        .iter()
        .filter(|record| record.origin.finding.run_id.is_none())
        .count();
    let (investigations, unaccounted) = source_investigations(root, &runs)?;
    let id = select_investigation(&investigations, preferred_investigation)?;
    Ok(LessonFollowupContext {
        lesson_count: records.len(),
        source_run_ids: runs.into_iter().collect(),
        unaccounted_source_runs: unaccounted + missing,
        allowance: id.map(|id| required_allowance(root, id)).transpose()?,
    })
}

fn source_investigations(
    root: &Path,
    runs: &BTreeSet<String>,
) -> Result<(BTreeSet<String>, usize)> {
    let db = crate::WorkspaceTarget::new(root)?.findings_db_path();
    let mut investigations = BTreeSet::new();
    let mut unaccounted = 0;
    for run in runs {
        match crate::SpendLimiter::read_run_provider_usage(&db, run)? {
            Some(usage) => {
                investigations.insert(usage.investigation_id);
            }
            None => unaccounted += 1,
        }
    }
    Ok((investigations, unaccounted))
}

fn select_investigation<'a>(
    sources: &'a BTreeSet<String>,
    preferred: Option<&'a str>,
) -> Result<Option<&'a str>> {
    if let Some(id) = preferred {
        return Ok(Some(id));
    }
    anyhow::ensure!(sources.len() <= 1,
        "These lessons span multiple investigations. Open a study in the intended investigation before reusing this context; no new budget was created");
    Ok(sources.first().map(String::as_str))
}

fn required_allowance(root: &Path, id: &str) -> Result<AllowanceSnapshot> {
    super::study_receipt::load_investigation_allowance(root, id)?
        .context("Recorded lesson investigation accounting is missing; restore it before new work")
}

#[cfg(test)]
mod tests;
