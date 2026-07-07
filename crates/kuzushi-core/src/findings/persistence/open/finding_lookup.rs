use super::*;

impl FindingStore {
    pub fn get_finding_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Finding>> {
        self.v3_finding_by_fingerprint(fingerprint)
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
