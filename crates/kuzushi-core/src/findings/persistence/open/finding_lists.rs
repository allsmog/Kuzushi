use super::*;
use std::collections::BTreeMap;

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
        let (count, mut findings) = collect_filtered_findings(self, all_findings, filter)?;
        self.attach_latest_verifications_to_findings(&mut findings)?;
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
    let mut review_cache = BTreeMap::new();
    for row in rows {
        count +=
            push_matching_finding(store, &mut review_cache, &mut findings, row, filter)? as usize;
    }
    Ok((count, findings))
}

fn push_matching_finding(
    store: &FindingStore,
    review_cache: &mut BTreeMap<String, Option<ReviewDecision>>,
    findings: &mut Vec<Finding>,
    finding: Finding,
    filter: &FindingListFilter,
) -> Result<bool> {
    let review_decision = latest_review_decision_for_filter(store, review_cache, &finding)?;
    if !filter.matches_with_review_decision(&finding, review_decision.as_ref()) {
        return Ok(false);
    }
    if filter.has_derived_triage_state_filter() {
        let lifecycle = store.stable_lifecycle_status_for_finding(&finding)?;
        // The fold reads the latest HUMAN decision, not the latest of any
        // author, so a later automated re-triage cannot mask a human verdict.
        let human_decision = latest_human_review_decision_for_filter(store, &finding)?;
        let derived = derive_triage_state(lifecycle, human_decision.as_ref());
        if !filter.matches_triage_lifecycle(&derived) {
            return Ok(false);
        }
    }
    if findings.len() < filter.limit {
        findings.push(finding);
    }
    Ok(true)
}

fn latest_review_decision_for_filter(
    store: &FindingStore,
    review_cache: &mut BTreeMap<String, Option<ReviewDecision>>,
    finding: &Finding,
) -> Result<Option<ReviewDecision>> {
    let Some(cache_key) = review_cache_key(finding) else {
        return Ok(None);
    };
    if let Some(decision) = review_cache.get(&cache_key) {
        return Ok(decision.clone());
    }
    let decision =
        load_latest_review_decision_for_filter(store, finding)?.map(|record| record.decision);
    review_cache.insert(cache_key, decision.clone());
    Ok(decision)
}

fn load_latest_review_decision_for_filter(
    store: &FindingStore,
    finding: &Finding,
) -> Result<Option<ReviewDecisionRecord>> {
    if let Some(identity_id) = finding.identity_id.as_deref() {
        return store.latest_review_decision_for_identity(identity_id);
    }
    match finding.id {
        Some(finding_id) => store.latest_review_decision(finding_id),
        None => Ok(None),
    }
}

fn latest_human_review_decision_for_filter(
    store: &FindingStore,
    finding: &Finding,
) -> Result<Option<ReviewDecision>> {
    let Some(finding_id) = finding.id else {
        return Ok(None);
    };
    Ok(store
        .latest_human_review_decision_for_finding_identity(finding_id)?
        .map(|record| record.decision))
}

fn review_cache_key(finding: &Finding) -> Option<String> {
    finding
        .identity_id
        .as_ref()
        .map(|identity_id| format!("identity:{identity_id}"))
        .or_else(|| finding.id.map(|finding_id| format!("finding:{finding_id}")))
}
