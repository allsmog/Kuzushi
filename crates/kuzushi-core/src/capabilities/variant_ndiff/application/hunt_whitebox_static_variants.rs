use super::derive_whitebox_variant_patterns::derive_whitebox_variant_patterns;
use super::*;

pub fn hunt_whitebox_static_variants(
    repo_root: impl AsRef<Path>,
    findings: &[Finding],
    evidence_store: Option<&StaticEvidenceStore>,
    max_variants: usize,
) -> Result<WhiteboxVariantSearchReport> {
    hunt_whitebox_static_variants_with_limits(
        repo_root,
        findings,
        evidence_store,
        max_variants,
        VariantSearchLimits::default(),
    )
}

pub(crate) fn hunt_whitebox_static_variants_with_limits(
    repo_root: impl AsRef<Path>,
    findings: &[Finding],
    evidence_store: Option<&StaticEvidenceStore>,
    max_variants: usize,
    limits: VariantSearchLimits,
) -> Result<WhiteboxVariantSearchReport> {
    let repo_root = repo_root.as_ref();
    let patterns = derive_whitebox_variant_patterns(findings, evidence_store)?;
    if max_variants == 0 {
        return Ok(empty_whitebox_variant_report(patterns));
    }

    let inventory = collect_variant_source_inventory(repo_root, limits)?;
    let (variants_by_key, mut truncation_reasons) = collect_whitebox_variant_candidates(
        repo_root,
        &patterns,
        &inventory.files,
        max_variants,
        limits,
    );
    truncation_reasons.extend(inventory.truncation_reasons);
    truncation_reasons.sort();
    truncation_reasons.dedup();
    let variants = variants_by_key.into_values().collect::<Vec<_>>();
    Ok(WhiteboxVariantSearchReport {
        count: variants.len(),
        patterns,
        variants,
        deterministic: true,
        truncated: !truncation_reasons.is_empty(),
        truncation_reasons,
    })
}

fn empty_whitebox_variant_report(
    patterns: Vec<WhiteboxVariantPattern>,
) -> WhiteboxVariantSearchReport {
    WhiteboxVariantSearchReport {
        count: 0,
        patterns,
        variants: Vec::new(),
        deterministic: true,
        truncated: false,
        truncation_reasons: Vec::new(),
    }
}

fn collect_whitebox_variant_candidates(
    repo_root: &Path,
    patterns: &[WhiteboxVariantPattern],
    source_files: &[PathBuf],
    max_variants: usize,
    limits: VariantSearchLimits,
) -> (BTreeMap<String, Finding>, Vec<String>) {
    let mut variants_by_key = BTreeMap::new();
    let mut truncation_reasons = Vec::new();
    let mut total_bytes = 0usize;
    for source_file in source_files {
        let Some(text) = read_variant_source(
            source_file,
            limits,
            &mut total_bytes,
            &mut truncation_reasons,
        ) else {
            continue;
        };
        collect_source_file_variants(
            repo_root,
            patterns,
            source_file,
            max_variants,
            &text,
            &mut variants_by_key,
        );
        if variant_limit_reached(&variants_by_key, max_variants) {
            truncation_reasons.push("variant_limit".to_string());
            break;
        }
    }
    (variants_by_key, truncation_reasons)
}

fn read_variant_source(
    source_file: &Path,
    limits: VariantSearchLimits,
    total_bytes: &mut usize,
    truncation_reasons: &mut Vec<String>,
) -> Option<String> {
    let file_bytes = source_file.metadata().ok()?.len() as usize;
    if file_bytes > limits.max_file_bytes {
        truncation_reasons.push("per_file_byte_limit".to_string());
        return None;
    }
    if total_bytes.saturating_add(file_bytes) > limits.max_total_bytes {
        truncation_reasons.push("total_byte_limit".to_string());
        return None;
    }
    let text = crate::bounded_file::read_utf8_text(source_file, limits.max_file_bytes).ok()?;
    *total_bytes = total_bytes.saturating_add(text.len());
    Some(text)
}

fn collect_source_file_variants(
    repo_root: &Path,
    patterns: &[WhiteboxVariantPattern],
    source_file: &Path,
    max_variants: usize,
    text: &str,
    variants_by_key: &mut BTreeMap<String, Finding>,
) {
    let Some(relative_path) = repo_relative_path(repo_root, source_file) else {
        return;
    };
    let lines = text.lines().collect::<Vec<_>>();
    for (line_index, line) in lines.iter().enumerate() {
        let window = line_window_from_lines(&lines, line_index, 2);
        for pattern in patterns {
            insert_line_variant_candidate(
                repo_root,
                pattern,
                &relative_path,
                line_index,
                line,
                &window,
                variants_by_key,
            );
            if variant_limit_reached(variants_by_key, max_variants) {
                return;
            }
        }
    }
}

fn line_window_from_lines(lines: &[&str], center: usize, radius: usize) -> String {
    let start = center.saturating_sub(radius);
    let end = (center + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}

fn insert_line_variant_candidate(
    repo_root: &Path,
    pattern: &WhiteboxVariantPattern,
    relative_path: &str,
    line_index: usize,
    line: &str,
    window: &str,
    variants_by_key: &mut BTreeMap<String, Finding>,
) {
    let line_no = u32::try_from(line_index + 1).unwrap_or(u32::MAX);
    if is_original_pattern_location(pattern, relative_path, line_no) {
        return;
    }
    let Some(candidate) =
        variant_candidate_from_window(repo_root, pattern, relative_path, line_no, window, line)
    else {
        return;
    };
    variants_by_key
        .entry(candidate.fingerprint.clone())
        .or_insert(candidate);
}

fn is_original_pattern_location(
    pattern: &WhiteboxVariantPattern,
    relative_path: &str,
    line_no: u32,
) -> bool {
    relative_path == pattern.file_path && line_no == pattern.start_line
}

fn variant_limit_reached(variants_by_key: &BTreeMap<String, Finding>, max_variants: usize) -> bool {
    variants_by_key.len() >= max_variants
}
