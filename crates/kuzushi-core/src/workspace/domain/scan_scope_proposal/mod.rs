//! Finite scope drafts and their coverage of an enumerated source snapshot.
use crate::workspace::RepositoryInventory;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod acceptance;
mod coverage;
mod editing;
mod identity_coverage;
mod inspection_limits;
mod paging;
pub use acceptance::ScopeCoverageApproval;
pub use editing::ScanScopeEdit;
pub use paging::{ScopeFileFilter, ScopeFilePage};
#[cfg(test)]
mod tests;
mod validation;

const MAX_PRIMARY_SCOPES: usize = 8;
const MAX_SCOPE_PATHS: usize = 32;
const MAX_EXCLUSIONS: usize = 128;
const MAX_COVERAGE_PREVIEW: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeDraft {
    pub schema_version: u32,
    pub scopes: Vec<ProposedScanScope>,
    pub shared_scope: Option<ProposedScanScope>,
    /// Shared context becomes discovery work only through this explicit choice.
    pub shared_discovery: bool,
    pub exclusions: Vec<ScanScopeExclusion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProposedScanScope {
    pub id: String,
    pub name: String,
    /// Exact repository-relative files or directory prefixes; no globs.
    pub paths: Vec<String>,
    pub rationale: String,
    pub shared_dependencies: Vec<String>,
    pub open_questions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeExclusion {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanScopeCoverage {
    pub enumeration_complete: bool,
    pub inventory_limited: bool,
    pub enumerated_files: usize,
    pub discovery_members: BTreeMap<String, ScopeFilePreview>,
    pub context_members: BTreeMap<String, ScopeFilePreview>,
    pub excluded_files: ScopeFilePreview,
    pub uncovered_files: ScopeFilePreview,
    pub overlaps: ScopeOverlapPreview,
    pub conflicting_exclusions: ScopeOverlapPreview,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeFilePreview {
    pub total: usize,
    pub files: Vec<String>,
}

impl ScopeFilePreview {
    fn record(&mut self, file: &str) {
        self.total += 1;
        if self.files.len() < MAX_COVERAGE_PREVIEW {
            self.files.push(file.into());
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeOverlapPreview {
    pub total: usize,
    pub files: BTreeMap<String, Vec<String>>,
}

impl ScopeOverlapPreview {
    fn record(&mut self, file: &str, owners: Vec<String>) {
        self.total += 1;
        if self.files.len() < MAX_COVERAGE_PREVIEW {
            self.files.insert(file.into(), owners);
        }
    }
}

impl ScanScopeDraft {
    /// Validate paths and references before computing any coverage claim.
    pub fn evaluate(&self, inventory: &RepositoryInventory) -> Result<ScanScopeCoverage> {
        let inspection = inventory.inspection.as_ref().context(
            "inventory membership is not recorded; rebuild inventory before scope planning",
        )?;
        let files = inspection
            .files
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        validation::validate(self, &files)?;
        Ok(coverage::evaluate(self, inventory, &files))
    }

    fn groups(&self) -> impl Iterator<Item = &ProposedScanScope> {
        self.scopes.iter().chain(self.shared_scope.iter())
    }
}

fn covers(path: &str, member: &str) -> bool {
    path == "."
        || member == path
        || member
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with('/'))
}
