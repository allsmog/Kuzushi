//! Read one coherent ledger projection independently of shell interaction state.
use super::*;
use kuzushi_core::findings::{IdentityFoldPolicy, ReviewDecisionRecord};
use kuzushi_core::workspace::WorkspaceReviewCompletion;
use kuzushi_core::{FindingListReport, PatchLifecycleRecord};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

mod failure;
mod page;
pub(crate) use failure::FindingsReadFailure;
use page::read_projection_page;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FindingsReadRequest {
    pub(crate) id: u64,
    pub(crate) expected_watermark: Option<u64>,
    pub(crate) operator_state: PathBuf,
    pub(crate) identity_fold: Option<String>,
    pub(crate) filter: Option<String>,
    pub(crate) batch_id: Option<String>,
    pub(crate) scan_run_refs: Option<Vec<String>>,
    pub(crate) page: kuzushi_core::findings::FindingPageRequest,
    pub(crate) prior_page_policy: String,
    pub(crate) recover_missing_anchor: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct FindingsReadSnapshot {
    pub(crate) target: PathBuf,
    pub(crate) watermark: Option<u64>,
    pub(crate) policy: IdentityFoldPolicy,
    pub(crate) report: FindingListReport,
    pub(crate) corpus: Vec<Finding>,
    pub(crate) review_decisions: Vec<ReviewDecisionRecord>,
    pub(crate) completion: Result<WorkspaceReviewCompletion, String>,
    pub(crate) legacy_lifecycles: Vec<PatchLifecycleRecord>,
    pub(crate) warnings: Vec<String>,
    pub(crate) page: kuzushi_core::findings::FindingPageMetadata,
    pub(crate) page_recovery_notice: Option<String>,
    pub(crate) study: Option<kuzushi_core::findings::BatchOccurrenceReport>,
}

pub(crate) fn read_findings_projection(
    target: &Path,
    request: &FindingsReadRequest,
) -> Result<FindingsReadSnapshot> {
    let mut filter = parse_read_filter(request.filter.as_deref())?;
    bind_review_batch(&mut filter, request.batch_id.as_deref())?;
    let target = target.to_path_buf();
    let (workspace, store, durable_projection) = open_projection_store(&target, request)?;
    let policy = read_identity_policy(workspace.root(), request)?;
    store.with_projection_snapshot(|store| {
        read_projection_snapshot(
            &workspace,
            store,
            durable_projection,
            &filter,
            policy,
            request,
        )
    })
}

fn read_projection_snapshot(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    durable_projection: bool,
    filter: &FindingListFilter,
    policy: IdentityFoldPolicy,
    request: &FindingsReadRequest,
) -> Result<FindingsReadSnapshot> {
    let watermark = store.projection_meta()?.applied_seq;
    let page = read_projection_page(store, workspace, filter, policy, request)?;
    let (corpus, scope_error) = read_corpus(
        store,
        workspace.root(),
        policy,
        request.scan_run_refs.as_deref(),
    )?;
    let review_decisions = store.list_all_review_decisions()?;
    let completion = read_source_completion(workspace, store, &corpus, scope_error.as_deref());
    let (legacy_lifecycles, mut warnings) = read_legacy_lifecycles(store);
    warnings.extend(scope_error);
    anyhow::ensure!(
        store.projection_meta()?.applied_seq == watermark,
        "Findings snapshot changed on its owning connection"
    );
    Ok(FindingsReadSnapshot {
        target: workspace.root().to_path_buf(),
        watermark: durable_projection.then_some(watermark),
        policy,
        report: page.report,
        corpus,
        review_decisions,
        completion,
        legacy_lifecycles,
        warnings,
        page: page.metadata,
        page_recovery_notice: page.recovery_notice,
        study: page.study,
    })
}

#[cfg(test)]
mod tests;

fn page_request_for_policy(
    request: &FindingsReadRequest,
    policy: IdentityFoldPolicy,
) -> kuzushi_core::findings::FindingPageRequest {
    let mut page = request.page.clone();
    if request.recover_missing_anchor && request.prior_page_policy != format!("{policy:?}") {
        page.anchor = None;
    }
    page
}

fn open_projection_store(
    target: &PathBuf,
    request: &FindingsReadRequest,
) -> Result<(WorkspaceTarget, FindingStore, bool)> {
    let workspace = WorkspaceTarget::new(target)?;
    require_previous_projection(&workspace, request)?;
    let durable_projection = workspace.findings_db_path().is_file();
    let (workspace, store) = open_finding_store_for_target_read_only(Some(target))?;
    Ok((workspace, store, durable_projection))
}

fn require_previous_projection(
    workspace: &WorkspaceTarget,
    request: &FindingsReadRequest,
) -> Result<()> {
    anyhow::ensure!(
        request.expected_watermark.is_none() || workspace.findings_db_path().is_file(),
        "Previously loaded findings ledger is unavailable; restore it or select a different target"
    );
    Ok(())
}

fn parse_read_filter(expression: Option<&str>) -> Result<FindingListFilter> {
    match expression {
        Some(expression) => FindingListFilter::from_filter_expression(expression),
        None => Ok(FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT)),
    }
}

fn bind_review_batch(filter: &mut FindingListFilter, selected: Option<&str>) -> Result<()> {
    let Some(selected) = selected else {
        return Ok(());
    };
    anyhow::ensure!(filter.batch_id.as_deref().is_none_or(|id| id == selected),
        "Study filter differs from the selected Review study; use batch clear or choose the same batchId");
    filter.batch_id = Some(selected.to_owned());
    Ok(())
}

fn read_source_completion(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    findings: &[Finding],
    scope_error: Option<&str>,
) -> Result<WorkspaceReviewCompletion, String> {
    if let Some(error) = scope_error {
        return Err(error.to_owned());
    }
    kuzushi_core::workspace::review_completion_for_findings(workspace, store, findings)
        .map_err(|error| error.to_string())
}

fn read_identity_policy(
    target: &Path,
    request: &FindingsReadRequest,
) -> Result<IdentityFoldPolicy> {
    let defaults = kuzushi_core::findings::resolve_identity_policy_defaults(
        &request.operator_state,
        target,
        request.identity_fold.as_deref(),
        None,
    )?;
    IdentityFoldPolicy::parse(Some(&defaults.identity_fold))
}

fn read_corpus(
    store: &FindingStore,
    target: &Path,
    policy: IdentityFoldPolicy,
    scan_run_refs: Option<&[String]>,
) -> Result<(Vec<Finding>, Option<String>)> {
    let mut findings = store.list_relevant_findings_with_identity_policy(policy)?;
    let Some(run_refs) = scan_run_refs else {
        return Ok((findings, None));
    };
    let run_refs = match kuzushi_core::run_artifacts::scan_finding_run_refs(target, run_refs) {
        Ok(refs) => refs.into_iter().collect::<BTreeSet<_>>(),
        Err(error) => {
            return Ok((
                findings,
                Some(format!(
                    "Selected scan membership is unavailable; counts use the full ledger: {error}"
                )),
            ))
        }
    };
    findings.retain(|finding| finding_observed_in_runs(finding, &run_refs));
    Ok((findings, None))
}

fn read_legacy_lifecycles(store: &FindingStore) -> (Vec<PatchLifecycleRecord>, Vec<String>) {
    match store.list_patch_lifecycle_current() {
        Ok(records) => (records, Vec::new()),
        Err(error) => (
            Vec::new(),
            vec![format!("could not load compatibility projection: {error}")],
        ),
    }
}
