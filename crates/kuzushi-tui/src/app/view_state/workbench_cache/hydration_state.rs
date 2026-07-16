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
            ViewHydrationKey::RunSummaryEntries => self
                .cached_run_summary_entries(Some(target))
                .is_not_requested(),
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
            ViewHydrationKey::GitMetadata => {
                self.cached_git_metadata(Some(target)).is_not_requested()
            }
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
        self.run_summary_entries = Some(RunSummaryEntriesCache { target, state });
        self.invalidate_run_summary_dependents();
    }

    fn store_run_artifact_text(
        &mut self,
        target: PathBuf,
        run_id: String,
        leaf: String,
        state: kuzushi_core::RunArtifactTextRead,
    ) {
        self.run_artifact_texts
            .insert((target, run_id, leaf), RunArtifactTextCache { state });
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
        self.run_traces
            .insert((target, run_id), RunTraceCache { state });
    }

    fn store_run_projection(
        &mut self,
        target: PathBuf,
        run_id: String,
        state: Result<kuzushi_core::run_lifecycle::RunProjectionRead, String>,
    ) {
        self.run_projections
            .insert((target, run_id), RunProjectionCache { state });
    }

    fn store_scan_stage_receipt(
        &mut self,
        target: PathBuf,
        run_id: String,
        state: ScanStageReceiptState,
    ) {
        self.scan_stage_receipts.insert((target, run_id), state);
    }

    fn apply_project_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
            (ViewHydrationKey::GitMetadata, ViewHydrationValue::GitMetadata(metadata)) => {
                self.git_metadata = Some(GitMetadataCache { target, metadata });
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
                self.json_files.insert(path, JsonFileCache { state });
            }
            (ViewHydrationKey::PathState { path }, ViewHydrationValue::PathState(state)) => {
                self.path_states.insert(path, PathStateCache { state });
            }
            (
                ViewHydrationKey::DirectoryListing { path },
                ViewHydrationValue::DirectoryListing(state),
            ) => {
                self.directory_listings
                    .insert(path, DirectoryListingCache { state });
            }
            (
                ViewHydrationKey::PromptOverrideHash { path },
                ViewHydrationValue::PromptOverrideHash(state),
            ) => self.prompt_overrides.store(path, state),
            _ => {}
        }
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
                self.health_checks.insert(credential_env, state);
            }
            (ViewHydrationKey::MapArtifacts, ViewHydrationValue::MapArtifacts(built)) => {
                self.map_artifacts.store(target, built);
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
        | ViewHydrationKey::FindingPatchTruth { .. } => HydrationGroup::Project,
        ViewHydrationKey::SourceFile { .. }
        | ViewHydrationKey::HarnessFile
        | ViewHydrationKey::JsonFile { .. }
        | ViewHydrationKey::PathState { .. }
        | ViewHydrationKey::DirectoryListing { .. }
        | ViewHydrationKey::PromptOverrideHash { .. } => HydrationGroup::Workspace,
        ViewHydrationKey::HealthChecks { .. }
        | ViewHydrationKey::TargetProfile
        | ViewHydrationKey::MapArtifacts
        | ViewHydrationKey::TargetBase => HydrationGroup::Status,
    }
}
