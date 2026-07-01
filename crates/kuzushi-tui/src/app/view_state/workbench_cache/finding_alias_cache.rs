use kuzushi_core::{sorted_finding_alias_indices, Finding, Severity};

#[derive(Debug, Default)]
pub(super) struct FindingAliasCache {
    cached: Option<CachedFindingAliases>,
}

impl FindingAliasCache {
    pub(super) fn sorted_indices(&mut self, findings: &[Finding]) -> Vec<(String, usize)> {
        let key = FindingAliasCacheKey::from_findings(findings);
        if let Some(cache) = self.cached.as_ref().filter(|cache| cache.key == key) {
            return cache.aliases.clone();
        }
        let aliases = sorted_finding_alias_indices(findings);
        self.cached = Some(CachedFindingAliases {
            key,
            aliases: aliases.clone(),
        });
        aliases
    }
}

#[derive(Debug)]
struct CachedFindingAliases {
    key: FindingAliasCacheKey,
    aliases: Vec<(String, usize)>,
}

#[derive(Debug, PartialEq, Eq)]
struct FindingAliasCacheKey {
    entries: Vec<FindingAliasCacheEntry>,
}

impl FindingAliasCacheKey {
    fn from_findings(findings: &[Finding]) -> Self {
        Self {
            entries: findings
                .iter()
                .map(FindingAliasCacheEntry::from_finding)
                .collect(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FindingAliasCacheEntry {
    fingerprint: String,
    severity: Severity,
}

impl FindingAliasCacheEntry {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            fingerprint: finding.fingerprint.clone(),
            severity: finding.severity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_alias_cache_refreshes_when_sort_keys_change() {
        let mut cache = FindingAliasCache::default();
        let mut first = Finding::new_semgrep("b", "src/b.rs", 1, None, Severity::High, "second");
        first.fingerprint = "b".to_string();
        let mut second = Finding::new_semgrep("a", "src/a.rs", 1, None, Severity::Medium, "first");
        second.fingerprint = "a".to_string();
        let mut findings = vec![first, second];

        let aliases = cache.sorted_indices(&findings);
        findings[1].severity = Severity::Critical;
        let refreshed = cache.sorted_indices(&findings);

        assert_eq!(aliases[0], ("F-0001".to_string(), 0));
        assert_eq!(refreshed[0], ("F-0001".to_string(), 1));
    }
}
