use super::*;
use kuzushi_core::workspace::ProjectModelDocument;

impl WorkbenchCache {
    pub(crate) fn cached_target_profile(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<TargetProfile> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .target_profile
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.profile);
        }
        self.loading_state(target, &ViewHydrationKey::TargetProfile)
    }

    pub(crate) fn cached_run_summary_entries(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<RunSummaryEntriesState> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .run_summary_entries
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(target, &ViewHydrationKey::RunSummaryEntries)
    }

    pub(crate) fn cached_run_summary_index(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<BTreeMap<String, RunSummary>> {
        match self.cached_run_summary_entries(target) {
            ViewDataState::Ready(RunSummaryEntriesState::Ready(entries)) => {
                ViewDataState::Ready(run_summary_index_from_entries(&entries))
            }
            ViewDataState::Ready(RunSummaryEntriesState::Failed(_)) => {
                ViewDataState::Ready(BTreeMap::new())
            }
            ViewDataState::Loading => ViewDataState::Loading,
            ViewDataState::NotRequested => ViewDataState::NotRequested,
        }
    }

    pub(crate) fn cached_source_file(
        &self,
        target: &Path,
        path: &Path,
    ) -> ViewDataState<Result<String, String>> {
        if let Some(cache) = self.source_file.as_ref().filter(|cache| cache.path == path) {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::SourceFile {
                path: path.to_path_buf(),
            },
        )
    }

    pub(crate) fn cached_git_metadata(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<Option<RunTargetGitMetadata>> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .git_metadata
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.metadata.clone());
        }
        self.loading_state(target, &ViewHydrationKey::GitMetadata)
    }

    pub(crate) fn cached_revision_relationship(
        &self,
        target: Option<&Path>,
        accepted_revision: &str,
        current_revision: &str,
    ) -> ViewDataState<kuzushi_core::workspace::RevisionRelationship> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        let key = (
            target.to_path_buf(),
            accepted_revision.to_string(),
            current_revision.to_string(),
        );
        if let Some(relationship) = self.revision_relationships.get(&key) {
            return ViewDataState::Ready(*relationship);
        }
        self.loading_state(
            target,
            &ViewHydrationKey::RevisionRelationship {
                accepted_revision: accepted_revision.to_string(),
                current_revision: current_revision.to_string(),
            },
        )
    }

    pub(crate) fn cached_project_scope_tree(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<ProjectScopeTreeState> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .scope_tree
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(target, &ViewHydrationKey::ProjectScopeTree)
    }

    pub(crate) fn cached_threat_model_store(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<ThreatModelStoreState> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some((_, state)) = self
            .threat_model_store
            .as_ref()
            .filter(|(cached_target, _)| cached_target == target)
        {
            return ViewDataState::Ready(state.clone());
        }
        self.loading_state(target, &ViewHydrationKey::ThreatModelStore)
    }

    pub(crate) fn cached_project_model_document(
        &self,
        target: Option<&Path>,
        scope_id: &str,
        revision: Option<&str>,
    ) -> ViewDataState<Option<ProjectModelDocument>> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self.project_model_document.as_ref().filter(|cache| {
            cache.target == target
                && cache.scope_id == scope_id
                && cache.revision.as_deref() == revision
        }) {
            return ViewDataState::Ready(cache.document.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::ProjectModelDocument {
                scope_id: scope_id.to_string(),
                revision: revision.map(str::to_string),
            },
        )
    }

    pub(crate) fn cached_strategy_queue(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<StrategyQueueState> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .strategy_queue
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(target, &ViewHydrationKey::StrategyQueue)
    }

    pub(crate) fn cached_prompt_mutations(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<PromptMutationsState> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .prompt_mutations
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(target, &ViewHydrationKey::PromptMutations)
    }

    pub(crate) fn cached_harness_file(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<Option<String>> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .harness_file
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.contents.clone());
        }
        self.loading_state(target, &ViewHydrationKey::HarnessFile)
    }

    pub(crate) fn cached_json_file(
        &self,
        target: &Path,
        path: &Path,
    ) -> ViewDataState<JsonFileState> {
        if let Some(cache) = self.json_files.get(path) {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::JsonFile {
                path: path.to_path_buf(),
            },
        )
    }

    pub(crate) fn cached_json_file_version(&self, path: &Path) -> Option<u64> {
        self.json_files.get(path).map(|cache| cache.version)
    }

    pub(crate) fn cached_json_file_content_sha256(&self, path: &Path) -> Option<String> {
        self.json_files
            .get(path)
            .and_then(|cache| cache.content_sha256.clone())
    }

    pub(crate) fn cached_entry_point_catalog_authentication(
        &self,
        path: &Path,
    ) -> Option<
        Result<kuzushi_core::capabilities::entry_points::EntryPointCatalogAuthentication, String>,
    > {
        self.json_files
            .get(path)
            .and_then(|cache| cache.entry_point_catalog_authentication.clone())
    }

    pub(crate) fn cached_entry_point_catalog_context_authentication(
        &self,
        path: &Path,
    ) -> Option<EntryPointCatalogContextAuthentication> {
        self.json_files
            .get(path)
            .and_then(|cache| cache.entry_point_catalog_context_authentication.clone())
    }

    pub(crate) fn cached_path_state(&self, target: &Path, path: &Path) -> ViewDataState<PathState> {
        if let Some(cache) = self.path_states.get(path) {
            return ViewDataState::Ready(cache.state);
        }
        self.loading_state(
            target,
            &ViewHydrationKey::PathState {
                path: path.to_path_buf(),
            },
        )
    }

    pub(crate) fn cached_directory_listing(
        &self,
        target: &Path,
        path: &Path,
    ) -> ViewDataState<DirectoryListingState> {
        if let Some(cache) = self.directory_listings.get(path) {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::DirectoryListing {
                path: path.to_path_buf(),
            },
        )
    }

    pub(crate) fn cached_prompt_override_hash(
        &self,
        target: &Path,
        path: &Path,
    ) -> ViewDataState<Result<Option<String>, String>> {
        if let Some(state) = self.prompt_overrides.cached(path) {
            return ViewDataState::Ready(state);
        }
        self.loading_state(
            target,
            &ViewHydrationKey::PromptOverrideHash {
                path: path.to_path_buf(),
            },
        )
    }

    pub(crate) fn cached_health_checks(
        &self,
        target: Option<&Path>,
        credential_env: &str,
    ) -> ViewDataState<ViewHealthChecks> {
        if let Some(checks) = self.health_checks.get(credential_env) {
            return ViewDataState::Ready(checks.clone());
        }
        self.loading_state(
            target.unwrap_or_else(|| Path::new(GLOBAL_HEALTH_HYDRATION_SCOPE)),
            &ViewHydrationKey::HealthChecks {
                credential_env: credential_env.to_string(),
            },
        )
    }
}
