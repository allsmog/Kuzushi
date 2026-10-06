use super::*;

impl ScanScopeDraft {
    /// Only included discovery/context members need immutable content identity.
    pub(crate) fn identity_omissions(
        &self,
        inventory: &RepositoryInventory,
        indexed_paths: &BTreeSet<String>,
    ) -> Result<ScopeFilePreview> {
        let inspection = inventory
            .inspection
            .as_ref()
            .context("inventory membership is unavailable")?;
        let files = inspection
            .files
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        validation::validate(self, &files)?;
        let mut omitted = ScopeFilePreview::default();
        for file in files {
            if !indexed_paths.contains(file) && self.includes_member(file) {
                omitted.record(file);
            }
        }
        Ok(omitted)
    }

    fn includes_member(&self, file: &str) -> bool {
        let excluded = self
            .exclusions
            .iter()
            .any(|exclusion| covers(&exclusion.path, file));
        !excluded
            && self
                .groups()
                .any(|scope| scope.paths.iter().any(|path| covers(path, file)))
    }
}
