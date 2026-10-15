//! Recorded observation commits remain distinct from the planned review source.
use super::*;
use crate::run_artifacts::{load_run_summary_without_repair, RunTargetGitMetadata};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewObservationSource {
    pub generation_id: i64,
    pub run_id: Option<String>,
    pub recorded_git: Option<RunTargetGitMetadata>,
    pub metadata_unavailable: bool,
}

pub(super) fn capture(root: &Path, findings: &[Finding]) -> Vec<ReviewObservationSource> {
    findings
        .iter()
        .map(|finding| source_for(root, finding))
        .collect()
}

fn source_for(root: &Path, finding: &Finding) -> ReviewObservationSource {
    let metadata = finding
        .scan_id
        .as_deref()
        .map(|run| load_run_summary_without_repair(root, run).map(|summary| summary.target_git))
        .transpose();
    let (recorded_git, metadata_unavailable) = match metadata {
        Ok(Some(Some(git))) if valid_recorded_git(&git) => (Some(git), false),
        Ok(None) | Ok(Some(None)) => (None, false),
        _ => (None, true),
    };
    ReviewObservationSource {
        generation_id: finding
            .id
            .expect("frozen review selection has generation ids"),
        run_id: finding.scan_id.clone(),
        recorded_git,
        metadata_unavailable,
    }
}

fn valid_commit(sha: &str) -> bool {
    matches!(sha.len(), 40 | 64) && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_recorded_git(git: &RunTargetGitMetadata) -> bool {
    valid_commit(&git.sha)
        && git
            .branch
            .as_ref()
            .is_none_or(|branch| branch.len() <= 256 && !branch.chars().any(char::is_control))
}

pub(super) fn from_plan(
    plan: &Value,
    findings: &[Finding],
) -> Result<Vec<ReviewObservationSource>> {
    let Some(value) = plan.get("observationSources") else {
        return Ok(Vec::new());
    };
    let sources: Vec<ReviewObservationSource> = serde_json::from_value(value.clone())?;
    anyhow::ensure!(
        sources.len() == findings.len(),
        "review observation source selection changed"
    );
    for (source, finding) in sources.iter().zip(findings) {
        anyhow::ensure!(
            source.generation_id == finding.id.unwrap_or_default()
                && source.run_id == finding.scan_id,
            "review observation source identity changed"
        );
        validate_recorded_source(source)?;
    }
    Ok(sources)
}

fn validate_recorded_source(source: &ReviewObservationSource) -> Result<()> {
    if let Some(git) = &source.recorded_git {
        anyhow::ensure!(
            !source.metadata_unavailable && source.run_id.is_some() && valid_recorded_git(git),
            "review observation has invalid recorded commit metadata"
        );
    }
    Ok(())
}
