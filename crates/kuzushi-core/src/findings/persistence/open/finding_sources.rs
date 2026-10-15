use super::*;

impl FindingStore {
    pub(crate) fn projected_finding_sources(
        &self,
        previous: Option<&Finding>,
        scan_id: &str,
        finding: &Finding,
    ) -> Vec<FindingSource> {
        let mut sources = previous
            .map(|finding| finding.sources.clone())
            .unwrap_or_default();
        merge_projected_source(&mut sources, scan_id, finding);
        sort_finding_sources(&mut sources);
        sources
    }
}

pub(super) fn merged_finding_sources(
    earlier: &[FindingSource],
    later: &[FindingSource],
) -> Vec<FindingSource> {
    crate::findings::merge_ordered_source_histories(earlier, later)
}

fn finding_source_signature(finding: &Finding) -> String {
    finding.source_signature.clone().unwrap_or_else(|| {
        let cwe = extract_cwe(&finding.rule_id, &finding.title, &finding.message);
        compute_source_signature(
            &finding.file_path,
            finding.start_line,
            cwe.as_deref().or(Some(finding.title.as_str())),
        )
    })
}

fn finding_seen_at(finding: &Finding) -> &str {
    if finding.created_at.trim().is_empty() {
        return "unknown";
    }
    &finding.created_at
}

fn merge_projected_source(sources: &mut Vec<FindingSource>, scan_id: &str, finding: &Finding) {
    let source_signature = finding_source_signature(finding);
    let seen_at = finding_seen_at(finding);
    merge_finding_source(
        sources,
        FindingSource {
            tool: finding.tool.clone(),
            vuln_source: finding.vuln_source,
            source_signature,
            first_scan_id: scan_id.to_string(),
            last_scan_id: scan_id.to_string(),
            first_seen_at: seen_at.to_string(),
            last_seen_at: seen_at.to_string(),
        },
    );
}

fn merge_finding_source(sources: &mut Vec<FindingSource>, incoming: FindingSource) {
    if let Some(existing) = sources
        .iter_mut()
        .find(|source| same_finding_source(source, &incoming))
    {
        if existing.vuln_source.is_none() {
            existing.vuln_source = incoming.vuln_source;
        }
        existing.last_scan_id = incoming.last_scan_id;
        existing.last_seen_at = incoming.last_seen_at;
        return;
    }
    sources.push(incoming);
}

fn same_finding_source(left: &FindingSource, right: &FindingSource) -> bool {
    left.tool == right.tool && left.source_signature == right.source_signature
}

fn sort_finding_sources(sources: &mut [FindingSource]) {
    sources.sort_by(|left, right| {
        left.tool
            .cmp(&right.tool)
            .then_with(|| left.source_signature.cmp(&right.source_signature))
    });
}
