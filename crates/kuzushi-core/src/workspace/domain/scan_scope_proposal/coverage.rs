use super::*;

pub(super) fn evaluate(
    draft: &ScanScopeDraft,
    inventory: &RepositoryInventory,
    files: &BTreeSet<&str>,
) -> ScanScopeCoverage {
    let mut coverage = ScanScopeCoverage {
        enumeration_complete: inventory.truncation.is_none(),
        inventory_limited: inventory_limited(inventory),
        enumerated_files: files.len(),
        discovery_members: BTreeMap::new(),
        context_members: BTreeMap::new(),
        excluded_files: ScopeFilePreview::default(),
        uncovered_files: ScopeFilePreview::default(),
        overlaps: ScopeOverlapPreview::default(),
        conflicting_exclusions: ScopeOverlapPreview::default(),
        limitations: inventory_limitations(inventory),
    };
    for member in files {
        record_member(&mut coverage, draft, member);
    }
    coverage
}

fn inventory_limited(inventory: &RepositoryInventory) -> bool {
    if inventory.truncation.is_some() {
        return true;
    }
    inventory.inspection.as_ref().is_none_or(|inspection| {
        !inspection.omitted_paths.is_empty() || !inspection.truncated_files.is_empty()
    })
}

fn record_member(coverage: &mut ScanScopeCoverage, draft: &ScanScopeDraft, member: &str) {
    let discovery = discovery_owners(draft, member);
    let context = context_owners(draft, member);
    if draft
        .exclusions
        .iter()
        .any(|exclusion| covers(&exclusion.path, member))
    {
        record_excluded(coverage, member, discovery);
        return;
    }
    if discovery.is_empty() {
        coverage.uncovered_files.record(member);
    }
    if discovery.len() > 1 {
        coverage.overlaps.record(member, discovery.clone());
    }
    add_members(&mut coverage.discovery_members, member, discovery);
    add_members(&mut coverage.context_members, member, context);
}

fn record_excluded(coverage: &mut ScanScopeCoverage, member: &str, discovery: Vec<String>) {
    coverage.excluded_files.record(member);
    if !discovery.is_empty() {
        coverage.conflicting_exclusions.record(member, discovery);
    }
}

fn add_members(
    members: &mut BTreeMap<String, ScopeFilePreview>,
    member: &str,
    owners: Vec<String>,
) {
    for owner in owners {
        members.entry(owner).or_default().record(member);
    }
}

pub(super) fn discovery_owners(draft: &ScanScopeDraft, member: &str) -> Vec<String> {
    let mut owners = owners(draft.scopes.iter(), member);
    if draft.shared_discovery {
        owners.extend(owners_for_shared(draft, member));
    }
    owners
}

fn context_owners(draft: &ScanScopeDraft, member: &str) -> Vec<String> {
    if draft.shared_discovery {
        return Vec::new();
    }
    owners_for_shared(draft, member)
}

fn owners_for_shared(draft: &ScanScopeDraft, member: &str) -> Vec<String> {
    owners(draft.shared_scope.iter(), member)
}

fn owners<'a>(groups: impl Iterator<Item = &'a ProposedScanScope>, member: &str) -> Vec<String> {
    groups
        .filter(|group| group.paths.iter().any(|path| covers(path, member)))
        .map(|group| group.id.clone())
        .collect()
}

fn inventory_limitations(inventory: &RepositoryInventory) -> Vec<String> {
    let mut lines = vec!["Coverage counts refer to enumerated files; ignored or inaccessible material is not included.".into()];
    if let Some(truncation) = &inventory.truncation {
        lines.push(format!("Partial inventory: {}", truncation.reason));
    }
    if let Some(inspection) = &inventory.inspection {
        lines.push(format!("Enumeration: {}; {} omitted paths; {} files inspected only in part; {} bytes inspected.",
            inspection.enumeration, inspection.omitted_paths.len(), inspection.truncated_files.len(), inspection.inspected_bytes));
    }
    lines
}
