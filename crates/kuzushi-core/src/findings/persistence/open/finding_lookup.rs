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
        if let Some(id) = reference.strip_prefix("generation:") {
            return self.finding_generation_by_id(id);
        }

        if let Some(finding) = self.get_finding_by_fingerprint(reference)? {
            return Ok(Some(finding));
        }

        self.hydrate_reference_match(reference, self.v3_reference_prefix_matches(reference)?)
    }

    fn finding_generation_by_id(&self, value: &str) -> Result<Option<Finding>> {
        let id: i64 = value
            .parse()
            .context("Finding generation id must be an integer")?;
        anyhow::ensure!(id > 0, "Finding generation id must be positive");
        let raw: Option<String> = self.conn.query_row(
            "select finding_json from finding_observations where cast(json_extract(finding_json,'$.id') as integer)=?1 order by created_seq desc limit 1",
            [id],|row| row.get(0),
        ).optional()?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let finding: Finding =
            serde_json::from_str(&raw).context("Finding generation is malformed")?;
        Ok(self.hydrate_v3_findings(vec![finding])?.pop())
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
