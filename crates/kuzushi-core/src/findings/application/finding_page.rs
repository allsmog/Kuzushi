//! Complete matching and snapshot-bound windows over the authoritative ledger.
use crate::findings::{
    Finding, FindingListFilter, FindingListReport, FindingStore, IdentityFoldPolicy,
};
use crate::{RunSummary, WorkspaceTarget};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

mod anchor;
mod batch_membership;
mod cursor;
mod scope_membership;
pub use anchor::{finding_page_anchor_index, finding_page_continuity_anchor};
use batch_membership::{matching_report, BatchPageMembership};
pub use scope_membership::FindingScopeFilterReceipt;
use scope_membership::ScopePageMembership;
#[cfg(test)]
mod tests;
use cursor::{page_offset, query_binding, window_report};

#[derive(Debug)]
pub struct FindingPageAnchorMissing;

impl std::fmt::Display for FindingPageAnchorMissing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Selected finding left this query; reload the first page")
    }
}

impl std::error::Error for FindingPageAnchorMissing {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingPageOrder {
    #[default]
    Ledger,
    Confidence,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct FindingPageRequest {
    pub cursor: Option<String>,
    pub anchor: Option<String>,
    pub order: FindingPageOrder,
}

impl FindingPageRequest {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let cursor = optional_text(input, "cursor")?;
        let anchor = optional_text(input, "anchor")?;
        anyhow::ensure!(
            cursor.is_none() || anchor.is_none(),
            "Choose a finding cursor or anchor, not both"
        );
        let order = match optional_text(input, "order")?.as_deref() {
            None | Some("ledger") => FindingPageOrder::Ledger,
            Some("confidence") => FindingPageOrder::Confidence,
            Some(_) => anyhow::bail!("findings:list order must be ledger or confidence"),
        };
        Ok(Self {
            cursor,
            anchor,
            order,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingPageMetadata {
    pub offset: usize,
    pub loaded: usize,
    pub total: usize,
    pub watermark: u64,
    pub order: FindingPageOrder,
    pub next_cursor: Option<String>,
    pub previous_cursor: Option<String>,
    pub anchors: Vec<String>,
    pub continuity_anchors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_filter: Option<FindingScopeFilterReceipt>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindingListPage {
    pub report: FindingListReport,
    pub page: FindingPageMetadata,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindingPageSnapshot {
    pub page: FindingListPage,
    pub study: Option<crate::findings::BatchOccurrenceReport>,
}

pub fn read_finding_page(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    filter: &FindingListFilter,
    policy: IdentityFoldPolicy,
    request: &FindingPageRequest,
) -> Result<FindingListPage> {
    read_finding_page_snapshot(store, workspace, filter, policy, request)
        .map(|snapshot| snapshot.page)
}

/// Returns the study summary used to determine membership and bind the cursor.
pub fn read_finding_page_snapshot(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    filter: &FindingListFilter,
    policy: IdentityFoldPolicy,
    request: &FindingPageRequest,
) -> Result<FindingPageSnapshot> {
    store.with_projection_snapshot(|store| {
        read_finding_page_projection(store, workspace, filter, policy, request)
    })
}

fn read_finding_page_projection(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    filter: &FindingListFilter,
    policy: IdentityFoldPolicy,
    request: &FindingPageRequest,
) -> Result<FindingPageSnapshot> {
    let before = store.projection_meta()?;
    let mut query = load_matching_query(store, workspace, filter, policy)?;
    order_matching_rows(&mut query.report, request.order);
    let binding = query_binding(workspace, filter, policy, request.order, &query)?;
    let offset = request_offset(
        request,
        &binding,
        &query.report,
        filter.limit.min(FindingListFilter::MAX_LIMIT),
    )?;
    anyhow::ensure!(
        before == store.projection_meta()?,
        "Findings changed while reading; reload the first page"
    );
    window_report(
        query.report,
        filter.limit.min(FindingListFilter::MAX_LIMIT),
        offset,
        &binding,
        before.applied_seq,
        request.order,
    )
    .map(|mut page| {
        page.page.scope_filter = query.scope.map(|scope| scope.receipt);
        FindingPageSnapshot {
            page,
            study: query.batch.map(|membership| membership.report),
        }
    })
}

pub fn finding_page_anchor(finding: &Finding) -> String {
    finding
        .id
        .map(|id| format!("generation:{id}"))
        .unwrap_or_else(|| format!("fingerprint:{}", finding.fingerprint))
}

pub(super) fn matching_report_with_provenance(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    filter: &FindingListFilter,
    policy: IdentityFoldPolicy,
) -> Result<FindingListReport> {
    let query = load_matching_query(store, workspace, filter, policy)?;
    anyhow::ensure!(query.scope.as_ref().is_none_or(|scope| scope.receipt.unavailable_runs.is_empty()),
        "Scope history is incomplete; inspect findings:list for unavailable runs before grouping findings");
    Ok(query.report)
}

struct MatchingPageQuery {
    report: FindingListReport,
    runs: BTreeMap<String, RunSummary>,
    batch: Option<BatchPageMembership>,
    scope: Option<ScopePageMembership>,
}

fn load_matching_query(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    filter: &FindingListFilter,
    policy: IdentityFoldPolicy,
) -> Result<MatchingPageQuery> {
    let runs = provenance_runs(workspace, filter)?;
    let batch = BatchPageMembership::load(store, workspace, filter.batch_id.as_deref(), policy)?;
    let scope = ScopePageMembership::load(store, workspace, filter, policy, batch.as_ref())?;
    let report = matching_report(store, filter, policy, batch.as_ref())?;
    let mut report = apply_provenance(report, filter, &runs);
    if let Some(scope) = &scope {
        scope.apply(&mut report);
    }
    Ok(MatchingPageQuery {
        report,
        runs,
        batch,
        scope,
    })
}

fn request_offset(
    request: &FindingPageRequest,
    binding: &str,
    report: &FindingListReport,
    limit: usize,
) -> Result<usize> {
    anyhow::ensure!(
        request.cursor.is_none() || request.anchor.is_none(),
        "Choose a finding cursor or anchor, not both"
    );
    let Some(anchor) = &request.anchor else {
        return page_offset(request.cursor.as_deref(), binding);
    };
    anyhow::ensure!(limit > 0, "An anchored finding page needs a positive limit");
    let index =
        finding_page_anchor_index(&report.findings, anchor).ok_or(FindingPageAnchorMissing)?;
    Ok(index / limit * limit)
}

fn optional_text(input: &Value, key: &str) -> Result<Option<String>> {
    input
        .get(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .with_context(|| format!("findings:list {key} must be a string"))
                .map(|value| value.trim().to_owned())
                .and_then(|value| {
                    anyhow::ensure!(!value.is_empty(), "findings:list {key} must not be empty");
                    Ok(value)
                })
        })
        .transpose()
}

fn provenance_runs(
    workspace: &WorkspaceTarget,
    filter: &FindingListFilter,
) -> Result<BTreeMap<String, RunSummary>> {
    if !filter.has_provenance_filter() || filter.has_scope_filter() {
        return Ok(BTreeMap::new());
    }
    Ok(crate::list_run_summaries(workspace.root())?
        .into_iter()
        .map(|run| (run.run_id.clone(), run))
        .collect())
}

fn apply_provenance(
    mut report: FindingListReport,
    filter: &FindingListFilter,
    runs: &BTreeMap<String, RunSummary>,
) -> FindingListReport {
    if filter.has_scope_filter() {
        return report;
    }
    let (findings, aliases) = report
        .findings
        .into_iter()
        .zip(report.aliases)
        .filter(|(finding, _)| filter.matches_run_provenance(finding, runs))
        .unzip();
    report.findings = findings;
    report.aliases = aliases;
    report.count = report.findings.len();
    report
}

fn order_matching_rows(report: &mut FindingListReport, order: FindingPageOrder) {
    if order == FindingPageOrder::Ledger {
        return;
    }
    let mut rows = std::mem::take(&mut report.findings)
        .into_iter()
        .zip(std::mem::take(&mut report.aliases))
        .collect::<Vec<_>>();
    rows.sort_by(|(left, _), (right, _)| {
        crate::findings::compare_findings_by_confidence(left, right)
    });
    (report.findings, report.aliases) = rows.into_iter().unzip();
}
