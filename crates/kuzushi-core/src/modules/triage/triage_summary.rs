use super::*;

pub(in crate::modules) fn triage_summary(
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    missing_fingerprints: &[String],
) -> String {
    let mut summary = format!(
        "[+] Triaged {} of {} findings (stage1 dropped {})\n      tp={}  fp={}  needs_review={}",
        stats.triaged(),
        stage1.total,
        stage1.dropped,
        stats.tp,
        stats.fp,
        stats.needs_review
    );
    append_by_design_summary(&mut summary, stats.by_design);
    summary.push_str(&format!("\n      cost=${:.4}", stats.total_cost));
    append_cost_cap_summary(&mut summary, stats);
    append_missing_fingerprints_summary(&mut summary, missing_fingerprints);
    summary
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
            Some(finding) if finding_matches_triage_scope(&finding, scan_id) => {
                push_triage_candidate(findings, seen, finding, input.retriage);
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
    for finding in store.list_findings(FindingListFilter::MAX_LIMIT)? {
        if finding_matches_triage_scope(&finding, scan_id) {
            push_triage_candidate(findings, seen, finding, input.retriage);
        }
    }
    Ok(())
}

fn effective_triage_scan_id(
    store: &FindingStore,
    input: &TriageRunInput,
) -> Result<Option<String>> {
    match &input.scan_id {
        Some(scan_id) => Ok(Some(scan_id.clone())),
        None => store.latest_scan_run_id(),
    }
}

fn finding_matches_triage_scope(finding: &Finding, scan_id: Option<&str>) -> bool {
    scan_id.is_none_or(|scan_id| finding.scan_id.as_deref() == Some(scan_id))
}

fn push_triage_candidate(
    findings: &mut Vec<Finding>,
    seen: &mut BTreeSet<String>,
    finding: Finding,
    retriage: bool,
) {
    if finding.triage.is_some() && !retriage {
        return;
    }
    if seen.insert(finding.fingerprint.clone()) {
        findings.push(finding);
    }
}
