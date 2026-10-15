//! Finite work attached to an allowance; consumed attempts survive revisions.
use super::domain::validate_identifier;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedWorkPlanV1 {
    pub schema_version: u32,
    pub campaign_id: String,
    pub plan_sha256: String,
    pub source_identity: String,
    pub config_sha256: String,
    pub jobs: Vec<ApprovedWorkItem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedWorkItem {
    pub work_id: String,
    pub tool: String,
    pub input_sha256: String,
    pub max_attempts: u32,
}

impl ApprovedWorkPlanV1 {
    pub(super) fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.schema_version == 1, "unsupported work plan version");
        validate_identifier(&self.campaign_id)?;
        anyhow::ensure!(
            (1..=100).contains(&self.jobs.len()),
            "work plan needs 1 to 100 jobs"
        );
        for digest in [&self.plan_sha256, &self.config_sha256] {
            validate_digest(digest)?;
        }
        anyhow::ensure!(
            !self.source_identity.is_empty(),
            "work plan needs source identity"
        );
        let mut ids = BTreeSet::new();
        for job in &self.jobs {
            job.validate()?;
            anyhow::ensure!(
                ids.insert(&job.work_id),
                "work plan contains duplicate work ids"
            );
        }
        Ok(())
    }

    pub fn job(&self, id: &str) -> Result<&ApprovedWorkItem> {
        self.jobs
            .iter()
            .find(|job| job.work_id == id)
            .context("work item is outside the approved finite plan")
    }
}

impl ApprovedWorkItem {
    pub(super) fn work_category(&self) -> Result<super::InvestigationWork> {
        match self.tool.as_str() {
            "sast:scan" => Ok(super::InvestigationWork::Discovery),
            "triage:run" => Ok(super::InvestigationWork::Review),
            "findings:lesson-generate"=>Ok(super::InvestigationWork::Learning),
            "planner:propose" => Ok(super::InvestigationWork::Scope),
            "threat-model:build"
                    | "threat-model:regenerate"
                    | "threat-model:ask"
            | "context:build"
            | "entry-points:extract"
            | "pack:suggest-scopes" => Ok(super::InvestigationWork::Context),
            _ => anyhow::bail!(
                "approved campaign work supports discovery scans, bounded context and workflow proposals, finding review and lesson drafts only"
            ),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_identifier(&self.work_id)?;
        self.work_category()?;
        validate_digest(&self.input_sha256)?;
        anyhow::ensure!(
            (1..=10).contains(&self.max_attempts),
            "job attempts must be between 1 and 10"
        );
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<()> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid work plan digest"
    );
    Ok(())
}

/// Values recomputed by shared dispatch, never accepted as model output.
pub struct WorkAttempt<'a> {
    pub reference: &'a super::AllowanceReferenceV1,
    pub run_id: &'a str,
    pub tool: &'a str,
    pub input_sha256: &'a str,
    pub source_identity: &'a str,
    pub config_sha256: &'a str,
}
