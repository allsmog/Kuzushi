use super::*;

impl WorkbenchCache {
    pub(crate) fn view_hydration_needed(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        match hydration_group(key) {
            HydrationGroup::Completion => self.completion_hydration_needed(target, key),
            HydrationGroup::Run => self.run_hydration_needed(target, key),
            HydrationGroup::Project => self.project_hydration_needed(target, key),
            HydrationGroup::Workspace => self.workspace_hydration_needed(target, key),
            HydrationGroup::Status => self.status_hydration_needed(target, key),
        }
    }

    pub(crate) fn mark_view_hydration_loading(&mut self, target: &Path, keys: &[ViewHydrationKey]) {
        self.hydrating_view_data
            .extend(keys.iter().cloned().map(|key| (target.to_path_buf(), key)));
    }

    pub(crate) fn clear_view_hydration_loading(&mut self) {
        self.hydrating_view_data.clear();
    }

    pub(crate) fn clear_failed_view_hydrations(&mut self, failures: &[ViewHydrationFailure]) {
        for failure in failures {
            self.hydrating_view_data
                .remove(&(failure.target.clone(), failure.key.clone()));
        }
    }

    pub(crate) fn apply_view_hydration(&mut self, result: ViewHydrationResult) {
        let ViewHydrationResult { target, key, value } = result;
        self.hydrating_view_data
            .remove(&(target.clone(), key.clone()));
        match hydration_group(&key) {
            HydrationGroup::Completion => self.apply_completion_hydration(target, key, value),
            HydrationGroup::Run => self.apply_run_hydration(target, key, value),
            HydrationGroup::Project => self.apply_project_hydration(target, key, value),
            HydrationGroup::Workspace => self.apply_workspace_hydration(target, key, value),
            HydrationGroup::Status => self.apply_status_hydration(target, key, value),
        }
    }

    fn run_hydration_needed(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        match key {
            ViewHydrationKey::LatestRunPointer => self
                .cached_latest_run_pointer(Some(target))
                .is_not_requested(),
            ViewHydrationKey::RunSummaryEntries => self.run_summary_entries_need_refresh(target),
            ViewHydrationKey::RunArtifactText { run_id, leaf } => self
                .cached_run_artifact_text(target, run_id, leaf)
                .is_not_requested(),
            ViewHydrationKey::RunTrace { run_id } => {
                self.cached_run_trace(target, run_id).is_not_requested()
            }
            ViewHydrationKey::RunProjection { run_id } => self
                .cached_run_projection(target, run_id)
                .is_not_requested(),
            ViewHydrationKey::ScanStageReceipt { run_id } => self
                .cached_scan_stage_receipt(target, run_id)
                .is_not_requested(),
            _ => false,
        }
    }

    fn project_hydration_needed(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        match key {
            ViewHydrationKey::GitMetadata => self.git_metadata_needs_refresh(target),
            ViewHydrationKey::ProjectScopeTree => self
                .cached_project_scope_tree(Some(target))
                .is_not_requested(),
            ViewHydrationKey::ProjectModelDocument { scope_id, revision } => self
                .cached_project_model_document(Some(target), scope_id, revision.as_deref())
                .is_not_requested(),
            ViewHydrationKey::StrategyQueue => {
                self.cached_strategy_queue(Some(target)).is_not_requested()
            }
            ViewHydrationKey::PromptMutations => self
                .cached_prompt_mutations(Some(target))
                .is_not_requested(),
            ViewHydrationKey::FindingPatchTruth {
                fingerprint,
                finding_scan_id,
                target_revision,
            } => self
                .cached_finding_patch_truth(
                    target,
                    fingerprint,
                    finding_scan_id.as_deref(),
                    target_revision.as_deref(),
                )
                .is_not_requested(),
            ViewHydrationKey::ScannedSnippet {
                stable_fp,
                scan_id,
                focus_line,
            } => self
                .cached_scanned_snippet(target, stable_fp, scan_id.as_deref(), *focus_line)
                .is_not_requested(),
            _ => false,
        }
    }

    fn workspace_hydration_needed(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        match key {
            ViewHydrationKey::SourceFile { path } => {
                self.cached_source_file(target, path).is_not_requested()
            }
            ViewHydrationKey::HarnessFile => {
                self.cached_harness_file(Some(target)).is_not_requested()
            }
            ViewHydrationKey::JsonFile { path } => {
                self.cached_json_file(target, path).is_not_requested()
            }
            ViewHydrationKey::PathState { path } => {
                self.cached_path_state(target, path).is_not_requested()
            }
            ViewHydrationKey::DirectoryListing { path } => self
                .cached_directory_listing(target, path)
                .is_not_requested(),
            ViewHydrationKey::PromptOverrideHash { path } => self
                .cached_prompt_override_hash(target, path)
                .is_not_requested(),
            _ => false,
        }
    }

    fn status_hydration_needed(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        match key {
            ViewHydrationKey::HealthChecks { credential_env } => self
                .cached_health_checks(Some(target), credential_env)
                .is_not_requested(),
            ViewHydrationKey::TargetProfile => {
                self.cached_target_profile(Some(target)).is_not_requested()
            }
            ViewHydrationKey::MapArtifacts => self
                .cached_map_artifacts_built(Some(target))
                .is_not_requested(),
            ViewHydrationKey::ScanRecommendations => self
                .cached_scan_recommendations(Some(target))
                .is_not_requested(),
            ViewHydrationKey::TargetBase => {
                self.cached_target_base(Some(target)).is_not_requested()
            }
            _ => false,
        }
    }

    fn apply_run_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
            (ViewHydrationKey::LatestRunPointer, ViewHydrationValue::LatestRunPointer(state)) => {
                self.store_latest_run_pointer(target, state)
            }
            (ViewHydrationKey::RunSummaryEntries, ViewHydrationValue::RunSummaryEntries(state)) => {
                self.store_run_summary_entries(target, state)
            }
            (
                ViewHydrationKey::RunArtifactText { run_id, leaf },
                ViewHydrationValue::RunArtifactText(state),
            ) => self.store_run_artifact_text(target, run_id, leaf, state),
            (ViewHydrationKey::RunTrace { run_id }, ViewHydrationValue::RunTrace(read)) => {
                self.store_run_trace(target, run_id, read)
            }
            (
                ViewHydrationKey::RunProjection { run_id },
                ViewHydrationValue::RunProjection(state),
            ) => self.store_run_projection(target, run_id, state),
            (
                ViewHydrationKey::ScanStageReceipt { run_id },
                ViewHydrationValue::ScanStageReceipt(state),
            ) => self.store_scan_stage_receipt(target, run_id, state),
            _ => {}
        }
    }

    fn store_latest_run_pointer(&mut self, target: PathBuf, state: LatestRunPointerState) {
        self.latest_run_pointer = Some(LatestRunPointerCache { target, state });
    }

    fn store_run_summary_entries(&mut self, target: PathBuf, state: RunSummaryEntriesState) {
        self.run_summary_entries = Some(RunSummaryEntriesCache {
            target,
            state,
            stale: false,
        });
        self.invalidate_run_summary_dependents();
    }

    fn store_run_artifact_text(
        &mut self,
        target: PathBuf,
        run_id: String,
        leaf: String,
        state: kuzushi_core::RunArtifactTextRead,
    ) {
        let key = (target, run_id, leaf);
        let bytes = run_artifact_text_bytes(&state);
        insert_bounded(
            &mut self.run_artifact_texts,
            key.clone(),
            RunArtifactTextCache { state, bytes },
            MAX_LARGE_RUN_CACHE_ENTRIES,
        );
        self.trim_large_run_caches(&LargeRunCacheKey::Artifact(key));
    }

    fn store_run_trace(
        &mut self,
        target: PathBuf,
        run_id: String,
        read: Option<kuzushi_core::RunTraceRead>,
    ) {
        let state = read
            .map(RunTraceCacheState::Ready)
            .unwrap_or(RunTraceCacheState::Invalid);
        let key = (target, run_id);
        let bytes = run_trace_bytes(&state);
        insert_bounded(
            &mut self.run_traces,
            key.clone(),
            RunTraceCache { state, bytes },
            MAX_RUN_CACHE_ENTRIES,
        );
        self.trim_large_run_caches(&LargeRunCacheKey::Trace(key));
    }

    pub(super) fn store_run_projection(
        &mut self,
        target: PathBuf,
        run_id: String,
        state: Result<kuzushi_core::run_lifecycle::RunProjectionRead, String>,
    ) {
        let key = (target, run_id);
        let bytes = run_projection_bytes(&state);
        insert_bounded(
            &mut self.run_projections,
            key.clone(),
            RunProjectionCache { state, bytes },
            MAX_LARGE_RUN_CACHE_ENTRIES,
        );
        self.trim_large_run_caches(&LargeRunCacheKey::Projection(key));
    }

    fn store_scan_stage_receipt(
        &mut self,
        target: PathBuf,
        run_id: String,
        state: ScanStageReceiptState,
    ) {
        insert_bounded(
            &mut self.scan_stage_receipts,
            (target, run_id),
            state,
            MAX_RUN_CACHE_ENTRIES,
        );
    }

    fn apply_project_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
            (ViewHydrationKey::GitMetadata, ViewHydrationValue::GitMetadata(metadata)) => {
                self.git_metadata = Some(GitMetadataCache {
                    target,
                    metadata,
                    stale: false,
                });
            }
            (ViewHydrationKey::ProjectScopeTree, ViewHydrationValue::ProjectScopeTree(state)) => {
                self.scope_tree = Some(ScopeTreeCache { target, state });
            }
            (
                ViewHydrationKey::ProjectModelDocument { scope_id, revision },
                ViewHydrationValue::ProjectModelDocument(document),
            ) => self.store_project_model_document(target, scope_id, revision, document),
            (ViewHydrationKey::StrategyQueue, ViewHydrationValue::StrategyQueue(state)) => {
                self.strategy_queue = Some(StrategyQueueCache { target, state });
            }
            (ViewHydrationKey::PromptMutations, ViewHydrationValue::PromptMutations(state)) => {
                self.prompt_mutations = Some(PromptMutationsCache { target, state });
            }
            (
                ViewHydrationKey::FindingPatchTruth {
                    fingerprint,
                    finding_scan_id,
                    target_revision,
                },
                ViewHydrationValue::FindingPatchTruth(state),
            ) => self.store_hydrated_finding_patch_truth(
                target,
                fingerprint,
                finding_scan_id,
                target_revision,
                state,
            ),
            (
                ViewHydrationKey::ScannedSnippet {
                    stable_fp,
                    scan_id,
                    focus_line,
                },
                ViewHydrationValue::ScannedSnippet(state),
            ) => self.store_scanned_snippet(
                &target,
                &stable_fp,
                scan_id.as_deref(),
                focus_line,
                state,
            ),
            _ => {}
        }
    }

    fn store_project_model_document(
        &mut self,
        target: PathBuf,
        scope_id: String,
        revision: Option<String>,
        document: Option<kuzushi_core::workspace::ProjectModelDocument>,
    ) {
        self.project_model_document = Some(ProjectModelDocumentCache {
            target,
            scope_id,
            revision,
            document,
        });
    }

    fn store_hydrated_finding_patch_truth(
        &mut self,
        target: PathBuf,
        fingerprint: String,
        finding_scan_id: Option<String>,
        target_revision: Option<String>,
        state: FindingPatchTruthState,
    ) {
        self.store_finding_patch_truth(
            &target,
            &fingerprint,
            finding_scan_id.as_deref(),
            target_revision.as_deref(),
            state,
        );
    }

    fn apply_workspace_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
            (ViewHydrationKey::SourceFile { path }, ViewHydrationValue::SourceFile(state)) => {
                self.source_file = Some(SourceFileCache { path, state });
            }
            (ViewHydrationKey::HarnessFile, ViewHydrationValue::HarnessFile(contents)) => {
                self.harness_file = Some(HarnessFileCache { target, contents });
            }
            (ViewHydrationKey::JsonFile { path }, ViewHydrationValue::JsonFile(state)) => {
                self.store_json_file(path, state);
            }
            (ViewHydrationKey::PathState { path }, ViewHydrationValue::PathState(state)) => {
                self.store_path_state(path, state);
            }
            (
                ViewHydrationKey::DirectoryListing { path },
                ViewHydrationValue::DirectoryListing(state),
            ) => {
                self.store_directory_listing(path, state);
            }
            (
                ViewHydrationKey::PromptOverrideHash { path },
                ViewHydrationValue::PromptOverrideHash(state),
            ) => self.prompt_overrides.store(path, state),
            _ => {}
        }
    }

    fn store_json_file(&mut self, path: PathBuf, state: JsonFileState) {
        insert_bounded(
            &mut self.json_files,
            path,
            JsonFileCache { state },
            MAX_PATH_CACHE_ENTRIES,
        );
    }

    fn store_path_state(&mut self, path: PathBuf, state: PathState) {
        insert_bounded(
            &mut self.path_states,
            path,
            PathStateCache { state },
            MAX_PATH_CACHE_ENTRIES,
        );
    }

    fn store_directory_listing(&mut self, path: PathBuf, state: DirectoryListingState) {
        insert_bounded(
            &mut self.directory_listings,
            path,
            DirectoryListingCache { state },
            MAX_PATH_CACHE_ENTRIES,
        );
    }

    fn apply_status_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
            (
                ViewHydrationKey::HealthChecks { credential_env },
                ViewHydrationValue::HealthChecks(state),
            ) => {
                insert_bounded(
                    &mut self.health_checks,
                    credential_env,
                    state,
                    MAX_STATUS_CACHE_ENTRIES,
                );
            }
            (ViewHydrationKey::MapArtifacts, ViewHydrationValue::MapArtifacts(built)) => {
                self.map_artifacts.store(target, built);
            }
            (
                ViewHydrationKey::ScanRecommendations,
                ViewHydrationValue::ScanRecommendations(state),
            ) => {
                self.scan_recommendations = Some(ScanRecommendationsCache { target, state });
            }
            (ViewHydrationKey::TargetProfile, ViewHydrationValue::TargetProfile(profile)) => {
                self.target_profile = Some(TargetProfileCache { target, profile });
            }
            (ViewHydrationKey::TargetBase, ViewHydrationValue::TargetBase(base)) => {
                self.target_base = Some(TargetBaseCache { target, base });
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HydrationGroup {
    Completion,
    Run,
    Project,
    Workspace,
    Status,
}

fn hydration_group(key: &ViewHydrationKey) -> HydrationGroup {
    match key {
        ViewHydrationKey::FileCompletionValues
        | ViewHydrationKey::FindingCompletionValues
        | ViewHydrationKey::RunIdCompletionValues => HydrationGroup::Completion,
        ViewHydrationKey::LatestRunPointer
        | ViewHydrationKey::RunSummaryEntries
        | ViewHydrationKey::RunArtifactText { .. }
        | ViewHydrationKey::RunTrace { .. }
        | ViewHydrationKey::RunProjection { .. }
        | ViewHydrationKey::ScanStageReceipt { .. } => HydrationGroup::Run,
        ViewHydrationKey::GitMetadata
        | ViewHydrationKey::ProjectScopeTree
        | ViewHydrationKey::ProjectModelDocument { .. }
        | ViewHydrationKey::StrategyQueue
        | ViewHydrationKey::PromptMutations
        | ViewHydrationKey::FindingPatchTruth { .. }
        | ViewHydrationKey::ScannedSnippet { .. } => HydrationGroup::Project,
        ViewHydrationKey::SourceFile { .. }
        | ViewHydrationKey::HarnessFile
        | ViewHydrationKey::JsonFile { .. }
        | ViewHydrationKey::PathState { .. }
        | ViewHydrationKey::DirectoryListing { .. }
        | ViewHydrationKey::PromptOverrideHash { .. } => HydrationGroup::Workspace,
        ViewHydrationKey::HealthChecks { .. }
        | ViewHydrationKey::TargetProfile
        | ViewHydrationKey::MapArtifacts
        | ViewHydrationKey::ScanRecommendations
        | ViewHydrationKey::TargetBase => HydrationGroup::Status,
    }
}
