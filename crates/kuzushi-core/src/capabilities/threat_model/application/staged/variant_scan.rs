use super::super::*;

const MAX_SCAN_FILES: usize = 2_000;
const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_PATTERNS_PER_THREAT: usize = 3;
const MIN_PATTERN_LEN: usize = 4;
const MAX_PATTERN_LEN: usize = 120;
const MAX_SIBLING_SAMPLE: usize = 5;

pub(crate) struct VariantScanOutcome {
    pub(crate) scanned_files: usize,
    pub(crate) threats_with_patterns: usize,
    pub(crate) total_siblings: usize,
    pub(crate) likelihood_raised: usize,
}

/// Deterministic sibling scan: each threat's model-emitted `variantScan.patterns`
/// are treated as plain substrings (never regex, never shell — the patterns are
/// untrusted model output) over a bounded walk of the repository's source
/// files. Sibling counts feed the likelihood rule; they NEVER become evidence
/// rows ("evidence raises likelihood; it is not the threat").
pub(crate) fn run_variant_scan(target: &Path, document: &mut Value) -> Result<VariantScanOutcome> {
    let plans = threat_pattern_plans(document);
    let mut outcome = VariantScanOutcome {
        scanned_files: 0,
        threats_with_patterns: plans.len(),
        total_siblings: 0,
        likelihood_raised: 0,
    };
    if plans.is_empty() {
        return Ok(outcome);
    }
    let matches = scan_files(target, &plans, &mut outcome)?;
    apply_sibling_counts(document, &plans, &matches, &mut outcome);
    Ok(outcome)
}

struct ThreatPatternPlan {
    threat_index: usize,
    patterns: Vec<String>,
}

fn threat_pattern_plans(document: &Value) -> Vec<ThreatPatternPlan> {
    let Some(threats) = document.get("threats").and_then(Value::as_array) else {
        return Vec::new();
    };
    threats
        .iter()
        .enumerate()
        .filter_map(|(threat_index, threat)| {
            let patterns = sanitized_patterns(threat);
            (!patterns.is_empty()).then_some(ThreatPatternPlan {
                threat_index,
                patterns,
            })
        })
        .collect()
}

fn sanitized_patterns(threat: &Value) -> Vec<String> {
    threat
        .pointer("/variantScan/patterns")
        .and_then(Value::as_array)
        .map(|patterns| {
            patterns
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|pattern| (MIN_PATTERN_LEN..=MAX_PATTERN_LEN).contains(&pattern.len()))
                .take(MAX_PATTERNS_PER_THREAT)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

struct ThreatMatches {
    sibling_files: Vec<String>,
}

fn scan_files(
    target: &Path,
    plans: &[ThreatPatternPlan],
    outcome: &mut VariantScanOutcome,
) -> Result<Vec<ThreatMatches>> {
    let inventory = crate::workspace::build_repository_inventory(target)
        .context("variant scan: repository inventory failed")?;
    let mut matches: Vec<ThreatMatches> = plans
        .iter()
        .map(|_| ThreatMatches {
            sibling_files: Vec::new(),
        })
        .collect();
    for file in inventory.source_files.iter().take(MAX_SCAN_FILES) {
        let Ok(text) =
            crate::bounded_file::read_utf8_text(&target.join(&file.path), MAX_FILE_BYTES)
        else {
            continue;
        };
        outcome.scanned_files += 1;
        record_file_matches(&file.path, &text, plans, &mut matches);
    }
    Ok(matches)
}

fn record_file_matches(
    path: &str,
    text: &str,
    plans: &[ThreatPatternPlan],
    matches: &mut [ThreatMatches],
) {
    for (plan, threat_matches) in plans.iter().zip(matches.iter_mut()) {
        if plan.patterns.iter().any(|pattern| text.contains(pattern)) {
            threat_matches.sibling_files.push(path.to_string());
        }
    }
}

fn apply_sibling_counts(
    document: &mut Value,
    plans: &[ThreatPatternPlan],
    matches: &[ThreatMatches],
    outcome: &mut VariantScanOutcome,
) {
    let Some(threats) = document.get_mut("threats").and_then(Value::as_array_mut) else {
        return;
    };
    for (plan, threat_matches) in plans.iter().zip(matches.iter()) {
        let Some(threat) = threats.get_mut(plan.threat_index) else {
            continue;
        };
        let sibling_count = threat_matches.sibling_files.len();
        outcome.total_siblings += sibling_count;
        threat["variantScan"] = json!({
            "patterns": plan.patterns,
            "siblingCount": sibling_count,
            "siblingSample": threat_matches
                .sibling_files
                .iter()
                .take(MAX_SIBLING_SAMPLE)
                .collect::<Vec<_>>(),
        });
        if adjust_threat_likelihood(threat, sibling_count) {
            outcome.likelihood_raised += 1;
        }
    }
}

fn adjust_threat_likelihood(threat: &mut Value, sibling_count: usize) -> bool {
    let evidence_rows = threat
        .get("evidence")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let Some(base) = threat.get("likelihood").and_then(Value::as_str) else {
        return false;
    };
    let adjusted = adjusted_likelihood(base, evidence_rows, sibling_count);
    let raised = adjusted != base;
    threat["likelihood"] = json!(adjusted);
    raised
}

pub(crate) fn variant_scan_stats(outcome: &VariantScanOutcome) -> Value {
    json!({
        "scannedFiles": outcome.scanned_files,
        "threatsWithPatterns": outcome.threats_with_patterns,
        "totalSiblings": outcome.total_siblings,
        "likelihoodRaised": outcome.likelihood_raised,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_scan_counts_matching_files_and_bumps_likelihood() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        for name in ["a.c", "b.c", "c.c"] {
            std::fs::write(
                temp.path().join("src").join(name),
                "size_t n = len * count; memcpy(dst, src, n);\n",
            )
            .unwrap();
        }
        std::fs::write(temp.path().join("src/safe.c"), "int x = 1;\n").unwrap();
        let mut document = json!({
            "threats": [{
                "id": "T-1",
                "likelihood": "low",
                "evidence": [],
                "variantScan": {"patterns": ["len * count"]}
            }]
        });
        let outcome = run_variant_scan(temp.path(), &mut document).unwrap();
        assert_eq!(outcome.threats_with_patterns, 1);
        assert_eq!(outcome.total_siblings, 3);
        assert_eq!(outcome.likelihood_raised, 1, "3 siblings bumps one band");
        let scan = &document["threats"][0]["variantScan"];
        assert_eq!(scan["siblingCount"], json!(3));
        assert_eq!(document["threats"][0]["likelihood"], json!("possible"));
    }

    #[test]
    fn threats_without_patterns_are_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let mut document = json!({"threats": [{"id": "T-1", "likelihood": "low"}]});
        let outcome = run_variant_scan(temp.path(), &mut document).unwrap();
        assert_eq!(outcome.threats_with_patterns, 0);
        assert_eq!(document["threats"][0]["likelihood"], json!("low"));
    }

    #[test]
    fn too_short_patterns_are_rejected_as_noise() {
        let threat = json!({"variantScan": {"patterns": ["ab", "  ", "real_pattern("]}});
        assert_eq!(
            sanitized_patterns(&threat),
            vec!["real_pattern(".to_string()]
        );
    }
}
