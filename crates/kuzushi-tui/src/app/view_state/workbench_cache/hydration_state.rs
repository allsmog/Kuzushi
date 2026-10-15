use super::*;

impl WorkbenchCache {
    pub(crate) fn view_hydration_needed(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        match hydration_group(key) {
            HydrationGroup::Transient => false,
            HydrationGroup::Completion => self.completion_hydration_needed(target, key),
            HydrationGroup::Run => self.run_hydration_needed(target, key),
            HydrationGroup::StudyUsage => self.study_usage_hydration_needed(target, key),
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
            self.record_failed_study_usage(failure);
            self.record_failed_review_source(failure);
        }
    }

    pub(crate) fn apply_view_hydration(&mut self, result: ViewHydrationResult) {
        let ViewHydrationResult { target, key, value } = result;
        self.hydrating_view_data
            .remove(&(target.clone(), key.clone()));
        match hydration_group(&key) {
            HydrationGroup::Transient => {}
            HydrationGroup::Completion => self.apply_completion_hydration(target, key, value),
            HydrationGroup::Run => self.apply_run_hydration(target, key, value),
            HydrationGroup::StudyUsage => self.apply_study_usage_hydration(target, key, value),
            HydrationGroup::Project => self.apply_project_hydration(target, key, value),
            HydrationGroup::Workspace => self.apply_workspace_hydration(target, key, value),
            HydrationGroup::Status => self.apply_status_hydration(target, key, value),
        }
    }

    fn run_hydration_needed(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        match key {
            ViewHydrationKey::InvestigationReport { .. }
            | ViewHydrationKey::InvestigationStudyReport { .. } => self
                .cached_selected_report(Some(target), key)
                .is_not_requested(),
            ViewHydrationKey::LatestRunPointer => self
                .cached_latest_run_pointer(Some(target))
                .is_not_requested(),
            ViewHydrationKey::RunSummaryEntries => self.run_summary_entries_need_refresh(target),
            ViewHydrationKey::RunArtifactText { run_id, leaf } => self
                .cached_run_artifact_text(target, run_id, leaf)
                .is_not_requested(),
            ViewHydrationKey::RunProjection { run_id } => self
                .cached_run_projection(target, run_id)
                .is_not_requested(),
            ViewHydrationKey::PhaseReceiptOutcome { attempt_id } => self
                .cached_phase_receipt_outcome(target, attempt_id)
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
            ViewHydrationKey::RevisionRelationship {
                accepted_revision,
                current_revision,
            } => self.revision_relationship_hydration_needed(
                target,
                accepted_revision,
                current_revision,
            ),
            ViewHydrationKey::ProjectScopeTree => self
                .cached_project_scope_tree(Some(target))
                .is_not_requested(),
            ViewHydrationKey::ThreatModelStore => self
                .cached_threat_model_store(Some(target))
                .is_not_requested(),
            ViewHydrationKey::MapRunContext { run_refs } => self
                .cached_map_run_context(target, run_refs)
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
            _ => self.finding_hydration_needed(target, key),
        }
    }

    fn finding_hydration_needed(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        match key {
            key @ ViewHydrationKey::FindingReviewSource { .. } => self
                .cached_finding_review_source(target, key)
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
            ViewHydrationKey::FindingAuditDataflow { fingerprint } => self
                .cached_finding_audit_dataflow(target, fingerprint)
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

    fn revision_relationship_hydration_needed(
        &self,
        target: &Path,
        accepted_revision: &str,
        current_revision: &str,
    ) -> bool {
        self.cached_revision_relationship(Some(target), accepted_revision, current_revision)
            .is_not_requested()
    }

    fn workspace_hydration_needed(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        match key {
            ViewHydrationKey::FindingLessons { offset } => !self
                .lesson_pages
                .contains_key(&(target.to_path_buf(), *offset)),
            key @ ViewHydrationKey::FindingGroups(_) => !self
                .group_pages
                .contains_key(&(target.to_path_buf(), key.clone())),
            ViewHydrationKey::FindingRelationships { finding_id, offset } => !self
                .relationship_pages
                .contains_key(&(target.to_path_buf(), *finding_id, *offset)),
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
            ViewHydrationKey::ExecutableOptions { .. } => self
                .cached_executable_options(target, key)
                .is_not_requested(),
            ViewHydrationKey::HealthChecks { credential_env } => self
                .cached_health_checks(Some(target), credential_env)
                .is_not_requested(),
            ViewHydrationKey::TargetProfile => {
                self.cached_target_profile(Some(target)).is_not_requested()
            }
            ViewHydrationKey::MapArtifacts => self
                .cached_map_artifacts_built(Some(target))
                .is_not_requested(),
            ViewHydrationKey::CpgArtifacts => self
                .cached_cpg_artifacts_built(Some(target))
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
            (
                key @ (ViewHydrationKey::InvestigationReport { .. }
                | ViewHydrationKey::InvestigationStudyReport { .. }),
                ViewHydrationValue::InvestigationReport(state),
            ) => {
                self.investigation_report = Some((target, key, state));
            }
            (ViewHydrationKey::LatestRunPointer, ViewHydrationValue::LatestRunPointer(state)) => {
                self.store_latest_run_pointer(target, state)
            }
            (
                ViewHydrationKey::RunSummaryEntries,
                ViewHydrationValue::RunSummaryEntries(hydration),
            ) => self.store_run_summary_entries(target, hydration.state),
            (
                ViewHydrationKey::RunArtifactText { run_id, leaf },
                ViewHydrationValue::RunArtifactText(state),
            ) => self.store_run_artifact_text(target, run_id, leaf, state),
            (
                ViewHydrationKey::RunProjection { run_id },
                ViewHydrationValue::RunProjection(state),
            ) => self.store_run_projection(target, run_id, state),
            (
                ViewHydrationKey::PhaseReceiptOutcome { attempt_id },
                ViewHydrationValue::PhaseReceiptOutcome(state),
            ) => self.store_phase_receipt_outcome(target, attempt_id, state),
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
        let version = run_artifact_version(&state);
        insert_bounded(
            &mut self.run_artifact_texts,
            key.clone(),
            RunArtifactTextCache {
                state,
                bytes,
                version,
            },
            MAX_LARGE_RUN_CACHE_ENTRIES,
        );
        self.trim_large_run_caches(&LargeRunCacheKey::Artifact(key));
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

    fn store_phase_receipt_outcome(
        &mut self,
        target: PathBuf,
        attempt_id: String,
        state: Result<Option<kuzushi_core::workflow_attempts::PhaseAttemptOutcome>, String>,
    ) {
        insert_bounded(
            &mut self.phase_receipt_outcomes,
            (target, attempt_id),
            state,
            MAX_RUN_CACHE_ENTRIES,
        );
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
                self.store_git_metadata(target, metadata);
            }
            (
                ViewHydrationKey::RevisionRelationship {
                    accepted_revision,
                    current_revision,
                },
                ViewHydrationValue::RevisionRelationship(relationship),
            ) => {
                self.store_revision_relationship(
                    target,
                    accepted_revision,
                    current_revision,
                    relationship,
                );
            }
            (key, value) => self.apply_project_artifact_hydration(target, key, value),
        }
    }

    fn apply_project_artifact_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
            (ViewHydrationKey::ProjectScopeTree, ViewHydrationValue::ProjectScopeTree(state)) => {
                self.store_project_scope_tree(target, state);
            }
            (ViewHydrationKey::ThreatModelStore, ViewHydrationValue::ThreatModelStore(state)) => {
                self.threat_model_store = Some((target, state))
            }
            (
                ViewHydrationKey::MapRunContext { run_refs },
                ViewHydrationValue::MapRunContext(state),
            ) => {
                self.map_run_context.insert((target, run_refs), state);
            }
            (
                ViewHydrationKey::ProjectModelDocument { scope_id, revision },
                ViewHydrationValue::ProjectModelDocument(document),
            ) => self.store_project_model_document(target, scope_id, revision, document),
            (ViewHydrationKey::StrategyQueue, ViewHydrationValue::StrategyQueue(state)) => {
                self.store_strategy_queue(target, state);
            }
            (ViewHydrationKey::PromptMutations, ViewHydrationValue::PromptMutations(state)) => {
                self.store_prompt_mutations(target, state);
            }
            (key, value) => self.apply_finding_hydration(target, key, value),
        }
    }

    fn store_git_metadata(
        &mut self,
        target: PathBuf,
        metadata: Option<kuzushi_core::run_artifacts::RunTargetGitMetadata>,
    ) {
        self.git_metadata = Some(GitMetadataCache {
            target,
            metadata,
            stale: false,
        });
    }

    fn store_project_scope_tree(&mut self, target: PathBuf, state: ProjectScopeTreeState) {
        self.scope_tree = Some(ScopeTreeCache { target, state });
    }

    fn store_strategy_queue(&mut self, target: PathBuf, state: StrategyQueueState) {
        self.strategy_queue = Some(StrategyQueueCache { target, state });
    }

    fn store_prompt_mutations(&mut self, target: PathBuf, state: PromptMutationsState) {
        self.prompt_mutations = Some(PromptMutationsCache { target, state });
    }

    fn store_revision_relationship(
        &mut self,
        target: PathBuf,
        accepted_revision: String,
        current_revision: String,
        relationship: kuzushi_core::workspace::RevisionRelationship,
    ) {
        self.revision_relationships
            .insert((target, accepted_revision, current_revision), relationship);
    }

    fn apply_finding_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
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
            (key, value) => self.apply_finding_evidence_hydration(target, key, value),
        }
    }

    fn apply_finding_evidence_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
            (
                key @ ViewHydrationKey::FindingReviewSource { .. },
                ViewHydrationValue::FindingReviewSource(value),
            ) => self.store_finding_review_source(target, key, value),
            (
                ViewHydrationKey::FindingAuditDataflow { fingerprint },
                ViewHydrationValue::FindingAuditDataflow(state),
            ) => self.store_finding_audit_dataflow(&target, &fingerprint, state),
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
            (
                ViewHydrationKey::FindingLessons { offset },
                ViewHydrationValue::FindingLessons(page),
            ) => {
                self.lesson_pages.insert((target, offset), page);
            }
            (key @ ViewHydrationKey::FindingGroups(_), ViewHydrationValue::FindingGroups(page)) => {
                self.store_finding_groups(target, key, page)
            }
            (key, value) => self.apply_workspace_file_hydration(target, key, value),
        }
    }

    fn apply_workspace_file_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
            (
                ViewHydrationKey::FindingRelationships { finding_id, offset },
                ViewHydrationValue::FindingRelationships(page),
            ) => {
                self.relationship_pages
                    .insert((target, finding_id, offset), page);
            }
            (ViewHydrationKey::SourceFile { path }, ViewHydrationValue::SourceFile(state)) => {
                self.source_file = Some(SourceFileCache { path, state });
            }
            (ViewHydrationKey::HarnessFile, ViewHydrationValue::HarnessFile(contents)) => {
                self.harness_file = Some(HarnessFileCache { target, contents });
            }
            (ViewHydrationKey::JsonFile { path }, ViewHydrationValue::JsonFile(hydration)) => {
                self.store_json_file(path, hydration);
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

    fn store_json_file(&mut self, path: PathBuf, hydration: JsonFileHydration) {
        self.json_file_generation = self.json_file_generation.wrapping_add(1).max(1);
        insert_bounded(
            &mut self.json_files,
            path,
            JsonFileCache {
                state: hydration.state,
                version: self.json_file_generation,
                content_sha256: hydration.content_sha256,
                entry_point_catalog_authentication: hydration.entry_point_catalog_authentication,
                entry_point_catalog_context_authentication: hydration
                    .entry_point_catalog_context_authentication,
            },
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

    fn store_health_checks(&mut self, credential_env: String, state: ViewHealthChecks) {
        insert_bounded(
            &mut self.health_checks,
            credential_env,
            state,
            MAX_STATUS_CACHE_ENTRIES,
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
                key @ ViewHydrationKey::ExecutableOptions { .. },
                ViewHydrationValue::ExecutableOptions(missing),
            ) => {
                self.store_executable_options(target, key, missing);
            }
            (
                ViewHydrationKey::HealthChecks { credential_env },
                ViewHydrationValue::HealthChecks(state),
            ) => self.store_health_checks(credential_env, state),
            (ViewHydrationKey::MapArtifacts, ViewHydrationValue::MapArtifacts(built)) => {
                self.map_artifacts.store(target, built);
            }
            (ViewHydrationKey::CpgArtifacts, ViewHydrationValue::CpgArtifacts(built)) => {
                self.cpg_artifacts.store(target, built);
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
    Transient,
    Completion,
    Run,
    StudyUsage,
    Project,
    Workspace,
    Status,
}

fn hydration_group(key: &ViewHydrationKey) -> HydrationGroup {
    use ViewHydrationKey as Key;
    match key {
        Key::FindingsProjection(_) => HydrationGroup::Transient,
        Key::StudyHistory
        | Key::StudyUsageCatalogue
        | Key::StudyUsageRun { .. }
        | Key::ContextMatrixReport { .. } => HydrationGroup::StudyUsage,
        Key::FileCompletionValues | Key::FindingCompletionValues | Key::RunIdCompletionValues => {
            HydrationGroup::Completion
        }
        Key::LatestRunPointer
        | Key::InvestigationReport { .. }
        | Key::InvestigationStudyReport { .. }
        | Key::RunSummaryEntries
        | Key::RunArtifactText { .. }
        | Key::RunProjection { .. }
        | Key::PhaseReceiptOutcome { .. }
        | Key::ScanStageReceipt { .. } => HydrationGroup::Run,
        key => artifact_hydration_group(key),
    }
}

fn artifact_hydration_group(key: &ViewHydrationKey) -> HydrationGroup {
    use ViewHydrationKey as Key;
    match key {
        Key::GitMetadata
        | Key::RevisionRelationship { .. }
        | Key::ProjectScopeTree
        | Key::ThreatModelStore
        | Key::MapRunContext { .. }
        | Key::ProjectModelDocument { .. }
        | Key::StrategyQueue
        | Key::PromptMutations
        | Key::FindingPatchTruth { .. }
        | Key::FindingAuditDataflow { .. }
        | Key::FindingReviewSource { .. }
        | Key::ScannedSnippet { .. } => HydrationGroup::Project,
        Key::SourceFile { .. }
        | Key::FindingGroups(_)
        | Key::FindingRelationships { .. }
        | Key::FindingLessons { .. }
        | Key::HarnessFile
        | Key::JsonFile { .. }
        | Key::PathState { .. }
        | Key::DirectoryListing { .. }
        | Key::PromptOverrideHash { .. } => HydrationGroup::Workspace,
        Key::ExecutableOptions { .. }
        | Key::HealthChecks { .. }
        | Key::TargetProfile
        | Key::MapArtifacts
        | Key::CpgArtifacts
        | Key::ScanRecommendations
        | Key::TargetBase => HydrationGroup::Status,
        _ => unreachable!("completion, transient and run keys are classified first"),
    }
}

#[cfg(test)]
mod entry_point_authentication_tests {
    use super::*;

    #[test]
    fn catalog_authentication_from_worker_is_cached_without_recomputation() {
        let target = PathBuf::from("/target");
        let path = kuzushi_core::workspace::workspace_state_root(&target).join("entry-points.json");
        let mut cache = WorkbenchCache::default();

        cache.apply_view_hydration(ViewHydrationResult {
            target: target.clone(),
            key: ViewHydrationKey::JsonFile { path: path.clone() },
            value: ViewHydrationValue::JsonFile(JsonFileHydration {
                state: JsonFileState::Present(serde_json::json!({"entryPoints": []})),
                content_sha256: None,
                entry_point_catalog_authentication: Some(Err("worker auth".to_string())),
                entry_point_catalog_context_authentication: Some(
                    EntryPointCatalogContextAuthentication::Unavailable(
                        "worker context auth".to_string(),
                    ),
                ),
            }),
        });

        assert!(matches!(
            cache.cached_entry_point_catalog_authentication(&path),
            Some(Err(error)) if error == "worker auth"
        ));
        assert!(cache.cached_json_file_version(&path).is_some());
        assert!(matches!(
            cache.cached_entry_point_catalog_context_authentication(&path),
            Some(EntryPointCatalogContextAuthentication::Unavailable(error))
                if error == "worker context auth"
        ));
    }
}
