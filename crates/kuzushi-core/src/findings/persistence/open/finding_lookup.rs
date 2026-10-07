use super::*;

impl FindingStore {
    pub fn get_finding_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Finding>> {
        self.v3_finding_by_fingerprint(fingerprint)
    }

    /// Which of the batch's fingerprints the store already holds, checked
    /// before this run's observations are appended. A fingerprint in this set
    /// is a re-observation; the rest are new to the store.
    ///
    /// This answers only the fingerprint question. How many *findings* a batch
    /// changes is a different number, because cross-channel dedup merges two
    /// fingerprints sharing a `dedup_key` into one finding, and only the
    /// insertion knows which merges happened. `insert_findings_measuring_delta`
    /// is the measurement a receipt should carry.
    pub(in crate::findings::persistence::open) fn reobserved_fingerprints<'a>(
        &self,
        findings: &'a [Finding],
    ) -> Result<std::collections::BTreeSet<&'a str>> {
        let produced = findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let mut reobserved = std::collections::BTreeSet::new();
        for fingerprint in produced {
            if self.get_finding_by_fingerprint(fingerprint)?.is_some() {
                reobserved.insert(fingerprint);
            }
        }
        Ok(reobserved)
    }

    pub fn get_finding_by_reference(&self, reference: &str) -> Result<Option<Finding>> {
        let reference = reference.trim();
        if reference.is_empty() {
            anyhow::bail!("finding reference must not be empty");
        }

        if let Some(finding) = self.get_finding_by_fingerprint(reference)? {
            return Ok(Some(finding));
        }

        self.hydrate_reference_match(reference, self.v3_reference_prefix_matches(reference)?)
    }

    /// Resolve an operator-supplied reference: exact fingerprint, unambiguous
    /// fingerprint prefix, or positional alias (`F-0001`). Aliases are
    /// positional over the sorted whole ledger, so a clamped list would
    /// misresolve them — always fall back over every finding.
    pub fn get_finding_by_operator_reference(&self, reference: &str) -> Result<Option<Finding>> {
        if let Some(finding) = self.get_finding_by_reference(reference)? {
            return Ok(Some(finding));
        }
        let all = self.list_all_findings()?;
        Ok(crate::findings::resolve_finding_alias(&all, reference))
    }

    fn hydrate_reference_match(
        &self,
        reference: &str,
        matches: Vec<Finding>,
    ) -> Result<Option<Finding>> {
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.into_iter().next()),
            _ => anyhow::bail!("finding reference {reference:?} is ambiguous"),
        }
    }
}
