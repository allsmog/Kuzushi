use kuzushi_core::{
    sorted_finding_alias_indices, Finding, PersistedProofVerdict, Severity, StaticProofState,
    TriageVerdict,
};

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
    proof: FindingAliasProofCacheEntry,
}

impl FindingAliasCacheEntry {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            fingerprint: finding.fingerprint.clone(),
            severity: finding.severity,
            proof: FindingAliasProofCacheEntry::from_finding(finding),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FindingAliasProofCacheEntry {
    triage: Option<TriageVerdict>,
    triage_confidence: Option<u16>,
    verification: Option<PersistedProofVerdict>,
    static_proof: Option<StaticProofState>,
}

impl FindingAliasProofCacheEntry {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            triage: finding.triage.as_ref().map(|triage| triage.verdict),
            triage_confidence: finding
                .triage
                .as_ref()
                .map(|triage| (triage.confidence.clamp(0.0, 1.0) * 10_000.0).round() as u16),
            verification: finding
                .verification
                .as_ref()
                .map(|verification| verification.proof_verdict),
            static_proof: finding.static_proof_state,
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

    #[test]
    fn finding_alias_cache_refreshes_when_proof_state_changes() {
        let mut cache = FindingAliasCache::default();
        let mut guessed = Finding::new_semgrep("a", "src/a.rs", 1, None, Severity::High, "guess");
        guessed.fingerprint = "aaaa".to_string();
        let mut later = Finding::new_semgrep("z", "src/z.rs", 1, None, Severity::High, "later");
        later.fingerprint = "zzzz".to_string();
        let mut findings = vec![guessed, later];

        let aliases = cache.sorted_indices(&findings);
        findings[1].triage = Some(kuzushi_core::TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "confirmed".to_string(),
            cost_usd: 0.0,
        });
        let refreshed = cache.sorted_indices(&findings);

        assert_eq!(aliases[0], ("F-0001".to_string(), 0));
        assert_eq!(refreshed[0], ("F-0001".to_string(), 1));
    }
}
