use super::prelude::*;
use super::*;

pub fn hunt_whitebox_static_variants(
    repo_root: impl AsRef<Path>,
    findings: &[Finding],
    evidence_store: Option<&StaticEvidenceStore>,
    max_variants: usize,
) -> Result<WhiteboxVariantSearchReport> {
    let repo_root = repo_root.as_ref();
    let patterns = derive_whitebox_variant_patterns(findings, evidence_store)?;
    let mut variants_by_key = BTreeMap::new();
    if max_variants == 0 {
        return Ok(WhiteboxVariantSearchReport {
            count: 0,
            patterns,
            variants: Vec::new(),
            deterministic: true,
        });
    }

    let source_files = collect_variant_source_files(repo_root)?;
    for pattern in &patterns {
        for source_file in &source_files {
            let Some(relative_path) = repo_relative_path(repo_root, source_file) else {
                continue;
            };
            let text = match fs::read_to_string(source_file) {
                Ok(text) => text,
                Err(_) => continue,
            };
            for (line_index, line) in text.lines().enumerate() {
                let line_no = u32::try_from(line_index + 1).unwrap_or(u32::MAX);
                if relative_path == pattern.file_path && line_no == pattern.start_line {
                    continue;
                }
                let window = line_window(&text, line_index, 2);
                let Some(candidate) = variant_candidate_from_window(
                    repo_root,
                    pattern,
                    &relative_path,
                    line_no,
                    &window,
                    line,
                ) else {
                    continue;
                };
                variants_by_key
                    .entry(candidate.fingerprint.clone())
                    .or_insert(candidate);
                if variants_by_key.len() >= max_variants {
                    break;
                }
            }
            if variants_by_key.len() >= max_variants {
                break;
            }
        }
        if variants_by_key.len() >= max_variants {
            break;
        }
    }

    let variants = variants_by_key.into_values().collect::<Vec<_>>();
    Ok(WhiteboxVariantSearchReport {
        count: variants.len(),
        patterns,
        variants,
        deterministic: true,
    })
}

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
    patterns.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.original_fingerprint.cmp(&right.original_fingerprint))
    });
    Ok(patterns)
}
