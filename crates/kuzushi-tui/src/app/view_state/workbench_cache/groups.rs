use super::*;
impl WorkbenchCache {
    pub(crate) fn cached_finding_groups(
        &self,
        target: Option<&Path>,
        key: &ViewHydrationKey,
    ) -> ViewDataState<Result<kuzushi_core::findings::FindingGroupsPage, String>> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        match self.group_pages.get(&(target.to_path_buf(), key.clone())) {
            Some(page) => ViewDataState::Ready(page.clone()),
            None => ViewDataState::Loading,
        }
    }

    pub(crate) fn store_finding_groups(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        page: Result<kuzushi_core::findings::FindingGroupsPage, String>,
    ) {
        if self.group_pages.len() >= 8 {
            self.group_pages.pop_first();
        }
        self.group_pages.insert((target, key), page);
    }
}
