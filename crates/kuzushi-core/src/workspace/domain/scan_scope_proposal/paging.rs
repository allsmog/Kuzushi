use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ScopeFileFilter {
    Scope { scope_id: String },
    Uncovered,
    Excluded,
    Overlap,
    ConflictingExclusion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeFilePage {
    pub offset: usize,
    pub total: usize,
    pub files: Vec<String>,
}

impl ScanScopeDraft {
    /// Read beyond the bounded preview without duplicating every membership.
    pub fn file_page(
        &self,
        inventory: &RepositoryInventory,
        filter: ScopeFileFilter,
        offset: usize,
        size: usize,
    ) -> Result<ScopeFilePage> {
        anyhow::ensure!(
            size > 0 && size <= MAX_COVERAGE_PREVIEW,
            "file pages require 1 to 128 rows"
        );
        let inspection = inventory
            .inspection
            .as_ref()
            .context("inventory membership is not recorded")?;
        let files = inspection
            .files
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        validation::validate(self, &files)?;
        filter.validate(self)?;
        let mut page = ScopeFilePage {
            offset,
            total: 0,
            files: Vec::new(),
        };
        for file in files.into_iter().filter(|file| filter.includes(self, file)) {
            page.record(file, size);
        }
        page.offset = offset.min(page.total);
        Ok(page)
    }
}

impl ScopeFilePage {
    fn record(&mut self, file: &str, size: usize) {
        if self.total >= self.offset && self.files.len() < size {
            self.files.push(file.into());
        }
        self.total += 1;
    }
}

impl ScopeFileFilter {
    fn validate(&self, draft: &ScanScopeDraft) -> Result<()> {
        if let Self::Scope { scope_id } = self {
            anyhow::ensure!(
                draft.groups().any(|group| &group.id == scope_id),
                "unknown scope {scope_id}"
            );
        }
        Ok(())
    }

    fn includes(&self, draft: &ScanScopeDraft, file: &str) -> bool {
        let excluded = draft
            .exclusions
            .iter()
            .any(|exclusion| covers(&exclusion.path, file));
        match self {
            Self::Scope { scope_id } => !excluded && scope_contains(draft, scope_id, file),
            Self::Excluded => excluded,
            other => other.includes_discovery(draft, file, excluded),
        }
    }

    fn includes_discovery(&self, draft: &ScanScopeDraft, file: &str, excluded: bool) -> bool {
        if excluded != matches!(self, Self::ConflictingExclusion) {
            return false;
        }
        self.matches_owner_count(coverage::discovery_owners(draft, file).len())
    }

    fn matches_owner_count(&self, owners: usize) -> bool {
        match self {
            Self::Uncovered => owners == 0,
            Self::Overlap => owners > 1,
            Self::ConflictingExclusion => owners > 0,
            _ => false,
        }
    }
}

fn scope_contains(draft: &ScanScopeDraft, id: &str, file: &str) -> bool {
    draft
        .groups()
        .filter(|group| group.id == id)
        .any(|group| group.paths.iter().any(|path| covers(path, file)))
}
