//! Source-bound presentation groups never change finding identities or decisions.
use crate::findings::{Finding, FindingRelationship, FindingRelationshipEndpoint};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

mod graph;
mod read;
mod selection;
pub use read::{read_finding_groups, read_finding_groups_cancellable};

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FindingGroupsRequest {
    pub filter: Option<String>,
    pub run_ids: Vec<String>,
    pub group_id: Option<String>,
    pub expected_revision: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

impl FindingGroupsRequest {
    pub fn first_page() -> Self {
        Self {
            limit: 50,
            ..Self::default()
        }
    }
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (1..=200).contains(&self.limit) && self.offset <= 1_000_000,
            "Group page limit or offset is invalid"
        );
        anyhow::ensure!(
            (self.group_id.is_none() && self.offset == 0) || self.expected_revision.is_some(),
            "Paging or selecting a group requires its recorded content revision"
        );
        anyhow::ensure!(
            self.run_ids.len() <= 5000,
            "Too many selected run references"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingGroupMember {
    pub finding_id: i64,
    pub alias: String,
    pub title: String,
    pub location: String,
    pub severity: String,
    pub proof: String,
    pub recorded_decision: String,
    pub run_id: Option<String>,
    #[serde(default)]
    pub matching_run_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingReviewGroup {
    pub id: String,
    pub member_count: usize,
    pub representative: FindingGroupMember,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingGroupDiagnostics {
    pub inactive_duplicate_links: usize,
    pub related_variant_links: usize,
    pub uncertain_links: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingGroupsPage {
    pub schema_version: u32,
    pub ledger_watermark: u64,
    pub revision: String,
    #[serde(default)]
    pub selected_run_ids: Vec<String>,
    pub total_findings: usize,
    pub total_groups: usize,
    pub total_members: usize,
    pub offset: usize,
    pub has_more: bool,
    pub groups: Vec<FindingReviewGroup>,
    pub selected_group: Option<FindingReviewGroup>,
    pub members: Vec<FindingGroupMember>,
    pub diagnostics: FindingGroupDiagnostics,
}

struct ReviewGroup {
    indices: Vec<usize>,
    summary: FindingReviewGroup,
}

fn recorded_endpoint(finding: &Finding) -> Result<FindingRelationshipEndpoint> {
    Ok(FindingRelationshipEndpoint {
        stable_key: finding
            .identity_id
            .clone()
            .unwrap_or_else(|| finding.fingerprint.clone()),
        fingerprint: finding.fingerprint.clone(),
        finding_id: finding.id.context("Grouped finding id missing")?,
        run_id: finding.scan_id.clone(),
    })
}

#[cfg(test)]
mod tests;
