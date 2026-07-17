use super::*;

impl FindingStore {
    pub fn list_findings(&self, limit: usize) -> Result<Vec<Finding>> {
        Ok(self
            .list_findings_filtered(&FindingListFilter::with_limit(limit))?
            .findings)
    }

    pub fn list_findings_for_scan_id(&self, scan_id: &str) -> Result<Vec<Finding>> {
        self.v3_findings_for_scan_id(scan_id)
    }

    pub fn list_findings_filtered(&self, filter: &FindingListFilter) -> Result<FindingListReport> {
        let all_findings = self.v3_all_findings()?;
        let (count, findings) = collect_filtered_findings(self, all_findings, filter)?;
        Ok(FindingListReport { count, findings })
    }
}

fn collect_filtered_findings(
    store: &FindingStore,
    rows: Vec<Finding>,
    filter: &FindingListFilter,
) -> Result<(usize, Vec<Finding>)> {
    let mut count = 0;
    let mut findings = Vec::new();
    let review_cache = store.latest_review_decisions_for_findings(&rows, false)?;
    let human_review_cache = filter
        .has_derived_triage_state_filter()
        .then(|| store.latest_review_decisions_for_findings(&rows, true))
        .transpose()?
        .unwrap_or_default();
    let stable_fps = rows.iter().map(finding_stable_key).collect::<Vec<_>>();
    let lifecycle_cache = store.current_statuses_for(&stable_fps)?;
    for row in rows {
        count += push_matching_finding(
            &review_cache,
            &human_review_cache,
            &lifecycle_cache,
            &mut findings,
            row,
            filter,
        ) as usize;
    }
    Ok((count, findings))
}

fn push_matching_finding(
    review_cache: &std::collections::BTreeMap<String, ReviewDecision>,
    human_review_cache: &std::collections::BTreeMap<String, ReviewDecision>,
    lifecycle_cache: &std::collections::BTreeMap<String, String>,
    findings: &mut Vec<Finding>,
    finding: Finding,
    filter: &FindingListFilter,
) -> bool {
    let cache_key = review_cache_key(&finding);
    let review_decision = cache_key.as_ref().and_then(|key| review_cache.get(key));
    if !filter.matches_with_review_decision(&finding, review_decision) {
        return false;
    }
    if !matches_derived_filter(
        human_review_cache,
        lifecycle_cache,
        &finding,
        cache_key.as_deref(),
        filter,
    ) {
        return false;
    }
    if findings.len() < filter.limit {
        findings.push(finding);
    }
    true
}

fn matches_derived_filter(
    human_reviews: &std::collections::BTreeMap<String, ReviewDecision>,
    lifecycles: &std::collections::BTreeMap<String, String>,
    finding: &Finding,
    cache_key: Option<&str>,
    filter: &FindingListFilter,
) -> bool {
    if !filter.has_derived_triage_state_filter() {
        return true;
    }
    let lifecycle = lifecycles
        .get(&finding_stable_key(finding))
        .map(|status| StableLifecycleStatus::from_current_status(status))
        .unwrap_or(StableLifecycleStatus::Open);
    // Human review wins over later automated re-triage.
    let human_decision = cache_key.and_then(|key| human_reviews.get(key));
    filter.matches_triage_lifecycle(&derive_triage_state(lifecycle, human_decision))
}

fn review_cache_key(finding: &Finding) -> Option<String> {
    finding
        .identity_id
        .as_ref()
        .map(|identity_id| format!("identity:{identity_id}"))
        .or_else(|| finding.id.map(|finding_id| format!("finding:{finding_id}")))
}

fn finding_stable_key(finding: &Finding) -> String {
    finding
        .identity_id
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone())
}
