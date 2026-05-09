use super::*;

pub fn derive_whitebox_variant_patterns(
    findings: &[Finding],
    evidence_store: Option<&StaticEvidenceStore>,
) -> Result<Vec<WhiteboxVariantPattern>> {
    let mut patterns = Vec::new();
    for finding in findings
        .iter()
        .filter(|finding| finding.static_proof_state == Some(StaticProofState::StaticallyConfirmed))
    {
        let evidence_nodes = match evidence_store {
            Some(store) => store.list_nodes_for_finding(&finding.fingerprint)?,
            None => Vec::new(),
        };
        if let Some(pattern) = derive_whitebox_variant_pattern(finding, &evidence_nodes) {
            patterns.push(pattern);
        }
    }
    sort_variant_patterns(&mut patterns);
    Ok(patterns)
}

fn sort_variant_patterns(patterns: &mut [WhiteboxVariantPattern]) {
    patterns.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.original_fingerprint.cmp(&right.original_fingerprint))
    });
}
