use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;

use crate::FindingRow;

pub(crate) fn relativise(path: &str, target: &Path) -> String {
    if let Ok(p) = Path::new(path).canonicalize() {
        if let Ok(rel) = p.strip_prefix(target) {
            return rel.to_string_lossy().into_owned();
        }
    }
    path.trim_start_matches("./").to_string()
}

pub(crate) fn path_matches(finding_path: &str, oracle_path: &str) -> bool {
    let normalized_finding = finding_path.trim_start_matches("./");
    let normalized_oracle = oracle_path.trim_start_matches("./");

    if normalized_oracle.ends_with('/')
        || (!normalized_oracle.contains('.') && !normalized_oracle.is_empty())
    {
        let prefix = normalized_oracle.trim_end_matches('/');
        if prefix.is_empty() {
            return true;
        }
        return normalized_finding == prefix
            || normalized_finding.starts_with(&format!("{prefix}/"));
    }

    normalized_finding == normalized_oracle
        || normalized_finding.ends_with(&format!("/{normalized_oracle}"))
}

pub(crate) fn extract_cwes(re: &Regex, finding: &FindingRow) -> Vec<String> {
    let mut out = BTreeSet::new();
    for haystack in [&finding.message, &finding.rule_id, &finding.title] {
        for cap in re.captures_iter(haystack) {
            if let Some(num) = cap.get(1) {
                out.insert(format!("CWE-{}", num.as_str()));
            }
        }
    }
    out.into_iter().collect()
}

pub(crate) fn cwes_match(finding_cwes: &[String], oracle_cwes: &[String]) -> bool {
    if oracle_cwes.is_empty() {
        return true;
    }
    if finding_cwes.is_empty() {
        return false;
    }
    finding_cwes
        .iter()
        .any(|f| oracle_cwes.iter().any(|o| eq_ignore_case(f, o)))
}

pub(crate) fn cwe_match_or_no_oracle_cwe(finding_cwes: &[String], oracle_cwes: &[String]) -> bool {
    oracle_cwes.is_empty() || cwes_match(finding_cwes, oracle_cwes)
}

pub(crate) fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
