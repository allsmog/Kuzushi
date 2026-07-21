use super::*;

impl FindingStore {
    pub fn get_finding_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Finding>> {
        self.v3_finding_by_fingerprint(fingerprint)
    }

    /// Split the produced distinct fingerprints into store-new vs re-observed,
    /// checked against the store before this run's observations are appended.
    pub(crate) fn fingerprint_delta(&self, findings: &[Finding]) -> Result<(u64, u64)> {
        let produced = findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let mut updated = 0_u64;
        for fingerprint in &produced {
            if self.get_finding_by_fingerprint(fingerprint)?.is_some() {
                updated += 1;
            }
        }
        Ok((produced.len() as u64 - updated, updated))
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
