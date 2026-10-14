use super::*;

impl WorkbenchCache {
    pub(crate) fn cached_relationships(
        &self,
        target: Option<&Path>,
        finding_id: Option<i64>,
        offset: usize,
    ) -> ViewDataState<Result<kuzushi_core::findings::FindingRelationshipPage, String>> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        match self
            .relationship_pages
            .get(&(target.to_path_buf(), finding_id, offset))
        {
            Some(page) => ViewDataState::Ready(page.clone()),
            None => ViewDataState::Loading,
        }
    }
}
