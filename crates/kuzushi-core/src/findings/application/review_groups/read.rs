use super::*;
use crate::findings::{EffectiveReviewStateIndex, FindingStore};
use crate::WorkspaceTarget;

pub fn read_finding_groups(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    request: &FindingGroupsRequest,
) -> Result<FindingGroupsPage> {
    read_finding_groups_cancellable(store, workspace, request, || Ok(()))
}

pub fn read_finding_groups_cancellable(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    request: &FindingGroupsRequest,
    mut ensure_active: impl FnMut() -> Result<()>,
) -> Result<FindingGroupsPage> {
    request.validate()?;
    ensure_active()?;
    let watermark = store.projection_meta()?.applied_seq;
    let selection::Selection {
        findings,
        aliases,
        run_refs,
    } = selection::load(store, workspace, request)?;
    let relationships = read_relationships(store, &mut ensure_active)?;
    let (components, diagnostics) = graph::components(&findings, &relationships)?;
    let decisions = EffectiveReviewStateIndex::from_findings_and_decisions(
        &findings,
        &store.list_all_review_decisions()?,
    );
    let members = findings
        .iter()
        .zip(aliases)
        .map(|(finding, alias)| member(finding, alias, &decisions, &run_refs))
        .collect::<Result<Vec<_>>>()?;
    let groups = build_groups(components, &findings, &members)?;
    let revision = content_revision(workspace, &members, &relationships, &run_refs, request)?;
    require_revision(request, &revision)?;
    let mut page = window_groups(&groups, &members, request, watermark, diagnostics)?;
    page.revision = revision;
    page.selected_run_ids = run_refs.into_iter().collect();
    ensure_active()?;
    anyhow::ensure!(
        watermark == store.projection_meta()?.applied_seq,
        "Finding groups changed while reading; refresh the group list"
    );
    Ok(page)
}

fn require_revision(request: &FindingGroupsRequest, actual: &str) -> Result<()> {
    anyhow::ensure!(
        request
            .expected_revision
            .as_deref()
            .is_none_or(|value| value == actual),
        "Finding groups changed; refresh before paging or opening a member"
    );
    Ok(())
}

fn content_revision(
    workspace: &WorkspaceTarget,
    members: &[FindingGroupMember],
    relationships: &[FindingRelationship],
    run_refs: &std::collections::BTreeSet<String>,
    request: &FindingGroupsRequest,
) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(&(
        workspace.root(),
        members,
        relationships,
        run_refs,
        &request.filter,
        &request.run_ids,
    ))?)
    .to_hex()
    .to_string())
}

fn read_relationships(
    store: &FindingStore,
    ensure_active: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<FindingRelationship>> {
    let mut rows = Vec::new();
    let mut offset = 0;
    loop {
        ensure_active()?;
        let page = store.finding_relationships(None, 200, offset)?;
        rows.extend(page.rows);
        if !page.has_more {
            return Ok(rows);
        }
        offset += 200;
    }
}

fn member(
    finding: &Finding,
    alias: String,
    decisions: &EffectiveReviewStateIndex,
    run_refs: &std::collections::BTreeSet<String>,
) -> Result<FindingGroupMember> {
    Ok(FindingGroupMember {
        finding_id: finding.id.context("Grouped finding id missing")?,
        alias,
        title: finding.title.clone(),
        location: format!("{}:{}", finding.file_path, finding.start_line),
        severity: finding.severity.as_str().into(),
        proof: crate::findings::ProofConfidence::classify(finding)
            .label()
            .into(),
        recorded_decision: decisions
            .effective_decision_for(finding)
            .map(|decision| decision.decision_label())
            .unwrap_or_else(|| "needs_review".into()),
        run_id: finding.scan_id.clone(),
        matching_run_ids: selection::matching_runs(finding, run_refs),
    })
}

fn build_groups(
    components: Vec<Vec<usize>>,
    findings: &[Finding],
    members: &[FindingGroupMember],
) -> Result<Vec<ReviewGroup>> {
    let mut groups = Vec::new();
    for mut indices in components {
        indices.sort_by(|left, right| {
            crate::findings::compare_findings_by_confidence(&findings[*left], &findings[*right])
        });
        let endpoints = indices
            .iter()
            .map(|index| recorded_endpoint(&findings[*index]))
            .collect::<Result<Vec<_>>>()?;
        let id = group_id(endpoints)?;
        let representative = members[indices[0]].clone();
        groups.push(ReviewGroup {
            summary: FindingReviewGroup {
                id,
                member_count: indices.len(),
                representative,
            },
            indices,
        });
    }
    groups.sort_by(|left, right| {
        crate::findings::compare_findings_by_confidence(
            &findings[left.indices[0]],
            &findings[right.indices[0]],
        )
    });
    Ok(groups)
}

fn group_id(mut endpoints: Vec<FindingRelationshipEndpoint>) -> Result<String> {
    endpoints.sort_by_key(|endpoint| endpoint.finding_id);
    Ok(format!(
        "group_{}",
        blake3::hash(&serde_json::to_vec(&endpoints)?).to_hex()
    ))
}

fn window_groups(
    groups: &[ReviewGroup],
    members: &[FindingGroupMember],
    request: &FindingGroupsRequest,
    watermark: u64,
    diagnostics: FindingGroupDiagnostics,
) -> Result<FindingGroupsPage> {
    let mut page = empty_page(
        groups.len(),
        members.len(),
        request.offset,
        watermark,
        diagnostics,
    );
    if let Some(id) = &request.group_id {
        return member_window(page, groups, members, request, id);
    }
    page.groups = groups
        .iter()
        .skip(request.offset)
        .take(request.limit)
        .map(|group| group.summary.clone())
        .collect();
    page.has_more = request.offset + page.groups.len() < groups.len();
    Ok(page)
}

fn empty_page(
    total_groups: usize,
    total_findings: usize,
    offset: usize,
    watermark: u64,
    diagnostics: FindingGroupDiagnostics,
) -> FindingGroupsPage {
    FindingGroupsPage {
        schema_version: 1,
        ledger_watermark: watermark,
        revision: String::new(),
        selected_run_ids: Vec::new(),
        total_findings,
        total_groups,
        total_members: 0,
        offset,
        has_more: false,
        groups: Vec::new(),
        selected_group: None,
        members: Vec::new(),
        diagnostics,
    }
}

fn member_window(
    mut page: FindingGroupsPage,
    groups: &[ReviewGroup],
    members: &[FindingGroupMember],
    request: &FindingGroupsRequest,
    id: &str,
) -> Result<FindingGroupsPage> {
    let group = groups
        .iter()
        .find(|group| group.summary.id == id)
        .context("Selected group no longer exists; refresh the group list")?;
    page.selected_group = Some(group.summary.clone());
    page.total_members = group.indices.len();
    page.members = group
        .indices
        .iter()
        .skip(request.offset)
        .take(request.limit)
        .map(|index| members[*index].clone())
        .collect();
    page.has_more = request.offset + page.members.len() < group.indices.len();
    Ok(page)
}
