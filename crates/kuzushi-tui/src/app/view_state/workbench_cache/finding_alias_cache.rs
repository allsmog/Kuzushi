use kuzushi_core::{sorted_finding_alias_indices, Finding, Severity};

#[derive(Debug, Default)]
pub(super) struct FindingAliasCache {
    cached: Option<CachedFindingAliases>,
}

impl FindingAliasCache {
    pub(super) fn sorted_indices(
        &mut self,
        findings: &[Finding],
        findings_revision: u64,
    ) -> Vec<(String, usize)> {
        if let Some(cache) = self
            .cached
            .as_ref()
            .filter(|cache| cache.findings_revision == findings_revision)
        {
            return cache.aliases.clone();
        }
        let aliases = sorted_finding_alias_indices(findings);
        self.cached = Some(CachedFindingAliases {
            findings_revision,
            aliases: aliases.clone(),
        });
        aliases
    }
}

#[derive(Debug)]
struct CachedFindingAliases {
    findings_revision: u64,
    aliases: Vec<(String, usize)>,
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

        let aliases = cache.sorted_indices(&findings, 1);
        findings[1].severity = Severity::Critical;
        let refreshed = cache.sorted_indices(&findings, 2);

        assert_eq!(aliases[0], ("F-0001".to_string(), 0));
        assert_eq!(refreshed[0], ("F-0001".to_string(), 1));
    }

    #[test]
    fn finding_alias_cache_keeps_aliases_stable_when_proof_state_changes() {
        let mut cache = FindingAliasCache::default();
        let mut guessed = Finding::new_semgrep("a", "src/a.rs", 1, None, Severity::High, "guess");
        guessed.fingerprint = "aaaa".to_string();
        let mut later = Finding::new_semgrep("z", "src/z.rs", 1, None, Severity::High, "later");
        later.fingerprint = "zzzz".to_string();
        let mut findings = vec![guessed, later];

        let aliases = cache.sorted_indices(&findings, 1);
        findings[1].triage = Some(kuzushi_core::TriageOutcome {
            verdict: kuzushi_core::TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "confirmed".to_string(),
            cost_usd: 0.0,
            cost_usd_exact: true,
        });
        let refreshed = cache.sorted_indices(&findings, 2);

        assert_eq!(aliases[0], ("F-0001".to_string(), 0));
        assert_eq!(refreshed[0], ("F-0001".to_string(), 0));
        assert_eq!(refreshed[1], ("F-0002".to_string(), 1));
    }
}
