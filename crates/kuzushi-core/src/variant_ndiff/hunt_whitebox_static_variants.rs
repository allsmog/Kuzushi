use super::derive_whitebox_variant_patterns::derive_whitebox_variant_patterns;
use super::*;

pub fn hunt_whitebox_static_variants(
    repo_root: impl AsRef<Path>,
    findings: &[Finding],
    evidence_store: Option<&StaticEvidenceStore>,
    max_variants: usize,
) -> Result<WhiteboxVariantSearchReport> {
    let repo_root = repo_root.as_ref();
    let patterns = derive_whitebox_variant_patterns(findings, evidence_store)?;
    if max_variants == 0 {
        return Ok(empty_whitebox_variant_report(patterns));
    }

    let source_files = collect_variant_source_files(repo_root)?;
    let variants_by_key =
        collect_whitebox_variant_candidates(repo_root, &patterns, &source_files, max_variants);
    let variants = variants_by_key.into_values().collect::<Vec<_>>();
    Ok(WhiteboxVariantSearchReport {
        count: variants.len(),
        patterns,
        variants,
        deterministic: true,
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
    }
}

fn collect_whitebox_variant_candidates(
    repo_root: &Path,
    patterns: &[WhiteboxVariantPattern],
    source_files: &[PathBuf],
    max_variants: usize,
) -> BTreeMap<String, Finding> {
    let mut variants_by_key = BTreeMap::new();
    for pattern in patterns {
        collect_pattern_variants(
            repo_root,
            pattern,
            source_files,
            max_variants,
            &mut variants_by_key,
        );
        if variant_limit_reached(&variants_by_key, max_variants) {
            break;
        }
    }
    variants_by_key
}

fn collect_pattern_variants(
    repo_root: &Path,
    pattern: &WhiteboxVariantPattern,
    source_files: &[PathBuf],
    max_variants: usize,
    variants_by_key: &mut BTreeMap<String, Finding>,
) {
    for source_file in source_files {
        collect_source_file_variants(
            repo_root,
            pattern,
            source_file,
            max_variants,
            variants_by_key,
        );
        if variant_limit_reached(variants_by_key, max_variants) {
            break;
        }
    }
}

fn collect_source_file_variants(
    repo_root: &Path,
    pattern: &WhiteboxVariantPattern,
    source_file: &Path,
    max_variants: usize,
    variants_by_key: &mut BTreeMap<String, Finding>,
) {
    let Some(relative_path) = repo_relative_path(repo_root, source_file) else {
        return;
    };
    let Ok(text) = fs::read_to_string(source_file) else {
        return;
    };
    for (line_index, line) in text.lines().enumerate() {
        insert_line_variant_candidate(
            repo_root,
            pattern,
            &relative_path,
            line_index,
            line,
            &text,
            variants_by_key,
        );
        if variant_limit_reached(variants_by_key, max_variants) {
            break;
        }
    }
}

fn insert_line_variant_candidate(
    repo_root: &Path,
    pattern: &WhiteboxVariantPattern,
    relative_path: &str,
    line_index: usize,
    line: &str,
    text: &str,
    variants_by_key: &mut BTreeMap<String, Finding>,
) {
    let line_no = u32::try_from(line_index + 1).unwrap_or(u32::MAX);
    if is_original_pattern_location(pattern, relative_path, line_no) {
        return;
    }
    let window = line_window(text, line_index, 2);
    let Some(candidate) =
        variant_candidate_from_window(repo_root, pattern, relative_path, line_no, &window, line)
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
