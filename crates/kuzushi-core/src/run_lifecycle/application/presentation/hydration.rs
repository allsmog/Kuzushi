use super::*;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunPresentationHydrationV1 {
    pub(super) results: BTreeMap<RunItemId, RunResultHydrationV1>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum RunResultHydrationV1 {
    Verified(crate::run_artifacts::RunResultSummary),
    Unavailable(SafeText),
}

impl RunPresentationHydrationV1 {
    pub(crate) fn insert_verified(
        &mut self,
        producing_item_id: RunItemId,
        summary: crate::run_artifacts::RunResultSummary,
    ) {
        self.results
            .insert(producing_item_id, RunResultHydrationV1::Verified(summary));
    }

    pub(crate) fn insert_unavailable(&mut self, producing_item_id: RunItemId, detail: SafeText) {
        self.results
            .insert(producing_item_id, RunResultHydrationV1::Unavailable(detail));
    }

    pub fn merge(&mut self, other: Self) {
        self.results.extend(other.results);
    }

    pub fn verified_summaries(&self) -> Vec<crate::run_artifacts::RunResultSummary> {
        self.results
            .values()
            .filter_map(verified_summary)
            .cloned()
            .collect()
    }
}

fn verified_summary(
    result: &RunResultHydrationV1,
) -> Option<&crate::run_artifacts::RunResultSummary> {
    match result {
        RunResultHydrationV1::Verified(summary) => Some(summary),
        RunResultHydrationV1::Unavailable(_) => None,
    }
}
