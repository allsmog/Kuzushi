use super::*;

impl WorkbenchCache {
    pub(crate) fn cached_file_completion_values(&self, target: Option<&Path>) -> &[String] {
        self.record_completion_source_read();
        cached_file_index(&self.file_completion_values, target)
            .map(|index| index.values.as_slice())
            .unwrap_or_default()
    }

    pub(crate) fn cached_file_completion_index(
        &self,
        target: Option<&Path>,
    ) -> Option<&FileCompletionIndex> {
        cached_file_index(&self.file_completion_values, target)
    }

    pub(crate) fn cached_finding_completion_values(&self, target: Option<&Path>) -> &[String] {
        self.record_completion_source_read();
        cached_values(&self.finding_completion_values, target)
    }

    pub(crate) fn cached_run_id_completion_values(&self, target: Option<&Path>) -> &[String] {
        self.record_completion_source_read();
        cached_values(&self.run_id_completion_values, target)
    }

    pub(crate) fn store_finding_completion_values(&mut self, target: &Path, values: Vec<String>) {
        if store_values(
            &mut self.finding_completion_values,
            target.to_path_buf(),
            values,
        ) {
            self.bump_completion_generation();
        }
    }

    pub(crate) fn completion_generations(&self) -> (u64, u64) {
        (self.completion_generation, self.command_provider_generation)
    }

    pub(crate) fn bump_completion_generation(&mut self) {
        self.completion_generation = self.completion_generation.wrapping_add(1);
    }

    pub(super) fn bump_completion_generation_when(&mut self, changed: bool) {
        if changed {
            self.bump_completion_generation();
        }
    }

    pub(crate) fn bump_command_provider_generation(&mut self) {
        self.command_provider_generation = self.command_provider_generation.wrapping_add(1);
    }

    #[cfg(test)]
    pub(crate) fn completion_source_reads(&self) -> usize {
        self.completion_source_reads.get()
    }

    pub(super) fn completion_hydration_needed(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> bool {
        let cached = match key {
            ViewHydrationKey::FileCompletionValues => {
                return !file_cache_matches_target(&self.file_completion_values, target);
            }
            ViewHydrationKey::FindingCompletionValues => &self.finding_completion_values,
            ViewHydrationKey::RunIdCompletionValues => &self.run_id_completion_values,
            _ => return false,
        };
        !cache_matches_target(cached, target)
    }

    pub(super) fn apply_completion_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        let stored = match (key, value) {
            (
                ViewHydrationKey::FileCompletionValues,
                ViewHydrationValue::FileCompletionValues(index),
            ) => store_file_index(&mut self.file_completion_values, target, index),
            (
                ViewHydrationKey::FindingCompletionValues,
                ViewHydrationValue::FindingCompletionValues(values),
            ) => store_values(&mut self.finding_completion_values, target, values),
            (
                ViewHydrationKey::RunIdCompletionValues,
                ViewHydrationValue::RunIdCompletionValues(values),
            ) => store_values(&mut self.run_id_completion_values, target, values),
            _ => false,
        };
        if stored {
            self.bump_completion_generation();
        }
    }

    #[cfg(test)]
    fn record_completion_source_read(&self) {
        self.completion_source_reads
            .set(self.completion_source_reads.get() + 1);
    }

    #[cfg(not(test))]
    fn record_completion_source_read(&self) {}
}

fn cached_values<'a>(
    cache: &'a Option<CompletionValuesCache>,
    target: Option<&Path>,
) -> &'a [String] {
    let Some(target) = target else {
        return &[];
    };
    cache
        .as_ref()
        .filter(|cache| cache.target == target)
        .map(|cache| cache.values.as_slice())
        .unwrap_or_default()
}

fn cache_matches_target(cache: &Option<CompletionValuesCache>, target: &Path) -> bool {
    cache.as_ref().is_some_and(|cache| cache.target == target)
}

fn cached_file_index<'a>(
    cache: &'a Option<FileCompletionValuesCache>,
    target: Option<&Path>,
) -> Option<&'a FileCompletionIndex> {
    let target = target?;
    cache
        .as_ref()
        .filter(|cache| cache.target == target)
        .map(|cache| &cache.index)
}

fn file_cache_matches_target(cache: &Option<FileCompletionValuesCache>, target: &Path) -> bool {
    cache.as_ref().is_some_and(|cache| cache.target == target)
}

fn store_file_index(
    cache: &mut Option<FileCompletionValuesCache>,
    target: PathBuf,
    index: FileCompletionIndex,
) -> bool {
    let changed = cache
        .as_ref()
        .is_none_or(|cached| cached.target != target || cached.index != index);
    if changed {
        *cache = Some(FileCompletionValuesCache { target, index });
    }
    changed
}

fn store_values(
    cache: &mut Option<CompletionValuesCache>,
    target: PathBuf,
    values: Vec<String>,
) -> bool {
    let changed = cache
        .as_ref()
        .is_none_or(|cached| cached.target != target || cached.values != values);
    if changed {
        *cache = Some(CompletionValuesCache { target, values });
    }
    changed
}
