use super::*;

pub(in crate::modules) fn triage_summary(
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    missing_fingerprints: &[String],
) -> String {
    let marker = if stats.result_status() == crate::module_result::ToolResultStatus::Completed {
        "[+]"
    } else {
        "[!]"
    };
    let mut summary = format!(
        "{marker} Triaged {} of {} findings (stage1 dropped {})\n      classifications attempted={} successful={} failed={}\n      tp={}  fp={}  needs_review={}",
        stats.triaged(),
        stage1.total,
        stage1.dropped,
        stats.attempted,
        stats.successful,
        stats.failed,
        stats.tp,
        stats.fp,
        stats.needs_review
    );
    append_by_design_summary(&mut summary, stats.by_design);
    append_degraded_operations(&mut summary, stats);
    append_classification_errors(&mut summary, stats);
    append_cost_summary(&mut summary, stats);
    append_cost_cap_summary(&mut summary, stats);
    append_missing_fingerprints_summary(&mut summary, missing_fingerprints);
    summary
}

fn append_degraded_operations(summary: &mut String, stats: &TriageRunStats) {
    if stats.vote_failures > 0 || stats.persistence_failures > 0 {
        summary.push_str(&format!(
            "\n[!] failed consensus votes={} persistence writes={}",
            stats.vote_failures, stats.persistence_failures
        ));
    }
}

fn append_classification_errors(summary: &mut String, stats: &TriageRunStats) {
    if !stats.error_summaries.is_empty() {
        summary.push_str(&format!(
            "\n[!] classification errors: {}",
            stats.error_summaries.join("; ")
        ));
    }
}

fn append_cost_summary(summary: &mut String, stats: &TriageRunStats) {
    let cost = stats.cost_report();
    if let Some(estimate) = cost.estimated_total_usd().filter(|_| cost.is_estimated()) {
        summary.push_str(&format!(
            "\n      estimated cost=~${estimate:.4} (tokens × list price; provider reported no charge)"
        ));
        return;
    }
    let label = if cost.is_complete() {
        "cost"
    } else {
        "observed cost (provider spend unresolved)"
    };
    summary.push_str(&format!("\n      {label}=${:.4}", cost.observed_usd()));
}

pub(in crate::modules) fn append_by_design_summary(summary: &mut String, by_design: usize) {
    if by_design > 0 {
        summary.push_str(&format!("  by_design={by_design}"));
    }
}

pub(in crate::modules) fn append_cost_cap_summary(summary: &mut String, stats: &TriageRunStats) {
    if stats.cost_cap_hit {
        summary.push_str(&format!(
            "\n[!] cost cap hit; {} finding(s) remain unevaluated",
            stats.pending_after_cap
        ));
    }
}

pub(in crate::modules) fn append_missing_fingerprints_summary(
    summary: &mut String,
    missing_fingerprints: &[String],
) {
    if !missing_fingerprints.is_empty() {
        summary.push_str(&format!(
            "\n[!] {} requested finding(s) were not found",
            missing_fingerprints.len()
        ));
    }
}

pub(in crate::modules) fn triage_tier_label(tier: ModelTier) -> &'static str {
    match tier {
        ModelTier::Cheap => "cheap",
        ModelTier::Mid => "mid",
        ModelTier::Deep => "deep",
    }
}

pub(in crate::modules) fn select_triage_findings(
    store: &FindingStore,
    input: &TriageRunInput,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    let scan_id = effective_triage_scan_id(store, input)?;

    let missing = match &input.fingerprints {
        Some(references) => select_referenced_triage_findings(
            store,
            input,
            scan_id.as_deref(),
            references,
            &mut findings,
            &mut seen,
        )?,
        None => {
            select_all_triage_findings(store, input, scan_id.as_deref(), &mut findings, &mut seen)?;
            Vec::new()
        }
    };

    Ok((findings, missing))
}

fn select_referenced_triage_findings(
    store: &FindingStore,
    input: &TriageRunInput,
    scan_id: Option<&str>,
    references: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut BTreeSet<String>,
) -> Result<Vec<String>> {
    let mut missing = Vec::new();
    for reference in references {
        match store.get_finding_by_reference(reference)? {
            Some(finding)
                if store.finding_is_relevant(&finding)?
                    && finding_matches_triage_scope(&finding, scan_id) =>
            {
                push_triage_candidate(store, findings, seen, finding, input.retriage)?;
            }
            _ => missing.push(reference.clone()),
        }
    }
    Ok(missing)
}

fn select_all_triage_findings(
    store: &FindingStore,
    input: &TriageRunInput,
    scan_id: Option<&str>,
    findings: &mut Vec<Finding>,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    let candidates = match scan_id {
        Some(_) => store.list_findings(FindingListFilter::MAX_LIMIT)?,
        None => store.list_relevant_findings()?,
    };
    for finding in candidates {
        if finding_matches_triage_scope(&finding, scan_id) {
            push_triage_candidate(store, findings, seen, finding, input.retriage)?;
        }
    }
    Ok(())
}

fn effective_triage_scan_id(
    store: &FindingStore,
    input: &TriageRunInput,
) -> Result<Option<String>> {
    if input.scope == TriageScope::All {
        // `None` matches every run: one bulk pass over all untriaged
        // findings regardless of which hunt module or run produced them.
        return Ok(None);
    }
    match &input.scan_id {
        Some(scan_id) => Ok(Some(scan_id.clone())),
        None => store.latest_run_id(),
    }
}

fn finding_matches_triage_scope(finding: &Finding, scan_id: Option<&str>) -> bool {
    scan_id.is_none_or(|scan_id| finding.scan_id.as_deref() == Some(scan_id))
}

fn push_triage_candidate(
    store: &FindingStore,
    findings: &mut Vec<Finding>,
    seen: &mut BTreeSet<String>,
    finding: Finding,
    retriage: bool,
) -> Result<()> {
    if !retriage && finding_has_review_decision(store, &finding)? {
        return Ok(());
    }
    if seen.insert(finding.fingerprint.clone()) {
        findings.push(finding);
    }
    Ok(())
}

fn finding_has_review_decision(store: &FindingStore, finding: &Finding) -> Result<bool> {
    if finding.triage.is_some() {
        return Ok(true);
    }
    if let Some(identity_id) = finding.identity_id.as_deref() {
        return Ok(store
            .latest_review_decision_for_identity(identity_id)?
            .is_some());
    }
    finding
        .id
        .map(|finding_id| store.latest_review_decision(finding_id))
        .transpose()
        .map(|decision| decision.flatten().is_some())
}
