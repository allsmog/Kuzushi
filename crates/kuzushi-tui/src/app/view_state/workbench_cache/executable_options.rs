use super::*;

impl WorkbenchCache {
    pub(super) fn store_executable_options(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        missing: Vec<String>,
    ) {
        insert_bounded(
            &mut self.executable_options,
            (target, key),
            missing,
            MAX_STATUS_CACHE_ENTRIES,
        );
    }

    pub(crate) fn executable_options_key(
        &self,
        requirements: Vec<kuzushi_core::modules::ExecutableRequirement>,
    ) -> ViewHydrationKey {
        ViewHydrationKey::ExecutableOptions {
            requirements,
            generation: self.executable_generation,
        }
    }

    pub(crate) fn cached_executable_options(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> ViewDataState<Vec<String>> {
        if let Some(missing) = self
            .executable_options
            .get(&(target.to_path_buf(), key.clone()))
        {
            return ViewDataState::Ready(missing.clone());
        }
        self.loading_state(target, key)
    }

    pub(crate) fn invalidate_executable_options(&mut self) {
        self.executable_options.clear();
        self.executable_generation = self.executable_generation.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_commands_and_refresh_cannot_reuse_a_previous_presence_result() {
        let mut cache = WorkbenchCache::default();
        let target = PathBuf::from("/owned");
        let requirements = vec![kuzushi_core::modules::ExecutableRequirement {
            option: "binary".into(),
            command: "/owned/first".into(),
        }];
        let old = cache.executable_options_key(requirements.clone());
        cache.apply_view_hydration(ViewHydrationResult {
            target: target.clone(),
            key: old.clone(),
            value: ViewHydrationValue::ExecutableOptions(vec!["binary".into()]),
        });
        assert_eq!(
            cache.cached_executable_options(&target, &old),
            ViewDataState::Ready(vec!["binary".into()])
        );
        let mut changed = requirements.clone();
        changed[0].command = "/owned/second".into();
        assert!(cache
            .cached_executable_options(&target, &cache.executable_options_key(changed))
            .is_not_requested());
        cache.invalidate_executable_options();
        let new = cache.executable_options_key(requirements);
        cache.apply_view_hydration(ViewHydrationResult {
            target: target.clone(),
            key: old,
            value: ViewHydrationValue::ExecutableOptions(Vec::new()),
        });
        assert!(cache
            .cached_executable_options(&target, &new)
            .is_not_requested());
    }
}
