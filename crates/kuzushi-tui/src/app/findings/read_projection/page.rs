use super::*;
use kuzushi_core::findings::{
    BatchOccurrenceReport, FindingPageAnchorMissing, FindingPageMetadata, FindingPageSnapshot,
};

pub(super) struct ReadFindingPage {
    pub(super) report: FindingListReport,
    pub(super) metadata: FindingPageMetadata,
    pub(super) recovery_notice: Option<String>,
    pub(super) study: Option<BatchOccurrenceReport>,
}

pub(super) fn read_projection_page(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    filter: &FindingListFilter,
    policy: IdentityFoldPolicy,
    request: &FindingsReadRequest,
) -> Result<ReadFindingPage> {
    let page_request = page_request_for_policy(request, policy);
    let first = kuzushi_core::findings::read_finding_page_snapshot(
        store,
        workspace,
        filter,
        policy,
        &page_request,
    );
    let (page, recovery_notice) = match first {
        Err(error) if request.recover_missing_anchor && error.is::<FindingPageAnchorMissing>() => {
            let fallback = kuzushi_core::findings::FindingPageRequest {
                anchor: None,
                ..page_request
            };
            let page = kuzushi_core::findings::read_finding_page_snapshot(
                store, workspace, filter, policy, &fallback,
            )?;
            (page, Some("Selected finding left this query. Showing the first page; recorded decisions remain.".to_string()))
        }
        other => (other?, None),
    };
    Ok(finish_page_read(page, recovery_notice))
}

fn finish_page_read(
    snapshot: FindingPageSnapshot,
    recovery_notice: Option<String>,
) -> ReadFindingPage {
    let notices = [recovery_notice, snapshot.study_gate_error]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let page = snapshot.page;
    ReadFindingPage {
        report: page.report,
        metadata: page.page,
        recovery_notice: (!notices.is_empty()).then(|| notices.join("\n")),
        study: snapshot.study,
    }
}
