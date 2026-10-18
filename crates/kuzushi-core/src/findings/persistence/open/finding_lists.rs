use super::*;
use crate::findings::application::project_finding_generations;
use crate::findings::IdentityFoldPolicy;

impl FindingStore {
    pub(in crate::findings) fn finding_fingerprints_observed_in_runs(
        &self,
        runs: &[String],
        policy: IdentityFoldPolicy,
    ) -> Result<std::collections::BTreeSet<String>> {
        let mut member_ids = std::collections::BTreeSet::new();
        for run in runs {
            member_ids.extend(
                self.list_findings_for_scan_id(run)?
                    .iter()
                    .filter_map(|row| row.id),
            );
        }
        Ok(
            crate::findings::application::representative_fingerprints_for_members(
                self.finding_generations_in_observation_order()?,
                policy,
                &member_ids,
            ),
        )
    }

    pub fn list_findings(&self, limit: usize) -> Result<Vec<Finding>> {
        Ok(self
            .list_findings_filtered(&FindingListFilter::with_limit(limit))?
            .findings)
    }

    pub fn list_findings_for_scan_id(&self, scan_id: &str) -> Result<Vec<Finding>> {
        self.v3_findings_for_scan_id(scan_id)
    }

    /// The shared run-scoped definition of "a finding": one row per
    /// identity-fold key under the policy the caller resolved. The ledger
    /// views an operator reads beside a scan receipt project the corpus
    /// through the effective policy, so a run-scoped reader that chooses its
    /// own reports a different total for the same runs on the same screen.
    ///
    /// Every caller must name a policy. A reader with no resolved policy in
    /// hand passes [`IdentityFoldPolicy::UNRESOLVED_RUN_SCOPE`], which says
    /// so, rather than letting this method pick one on its behalf.
    pub fn list_distinct_findings_for_scan_ids_with_identity_policy<S: AsRef<str>>(
        &self,
        run_ids: &[S],
        policy: IdentityFoldPolicy,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for run_id in run_ids {
            findings.extend(self.list_findings_for_scan_id(run_id.as_ref())?);
        }
        Ok(project_finding_generations(findings, policy))
    }

    /// Raw producer observations recorded by these runs, before same-issue
    /// corroboration folds them into findings.
    pub fn count_finding_observations_for_scan_ids<S: AsRef<str>>(
        &self,
        run_ids: &[S],
    ) -> Result<usize> {
        run_ids.iter().try_fold(0, |total, run_id| {
            Ok(total + self.v3_observation_count_for_scan_id(run_id.as_ref())?)
        })
    }

    /// Full-ledger fetch. Presentation lists clamp to
    /// `FindingListFilter::MAX_LIMIT`, but two consumers must see every
    /// finding: exports (which stamp completeness into metadata) and alias
    /// resolution (aliases are positional over the sorted whole ledger — a
    /// clamped subset both loses aliases past the limit and can assign the
    /// SAME alias to a different finding than the full set does).
    pub fn list_all_findings(&self) -> Result<Vec<Finding>> {
        self.v3_all_findings()
    }

    /// Findings that still belong to the active vulnerability corpus.
    ///
    /// A newer scan does not define this set: the durable lifecycle does.
    /// Agentic and otherwise non-deterministic findings therefore remain
    /// relevant when a later run does not rediscover them. Only an explicit
    /// suppression or rekey transition removes a row from active triage.
    /// A stale observation is a gap, not proof that the finding was fixed.
    pub fn list_relevant_findings(&self) -> Result<Vec<Finding>> {
        let findings = self.v3_all_findings()?;
        let stable_fps = findings.iter().map(finding_stable_key).collect::<Vec<_>>();
        let statuses = self.current_statuses_for(&stable_fps)?;
        Ok(findings
            .into_iter()
            .filter(|finding| finding_is_relevant_with_statuses(finding, &statuses))
            .collect())
    }

    pub fn finding_is_relevant(&self, finding: &Finding) -> Result<bool> {
        let key = finding_stable_key(finding);
        let statuses = self.current_statuses_for(std::slice::from_ref(&key))?;
        Ok(finding_is_relevant_with_statuses(finding, &statuses))
    }

    pub fn list_findings_filtered(&self, filter: &FindingListFilter) -> Result<FindingListReport> {
        let all_findings = self.v3_all_findings()?;
        collect_filtered_findings(self, all_findings, filter)
    }

    /// TUI-facing list whose identity collapse is chosen by the effective
    /// operator policy rather than baked into the compatibility projection.
    pub fn list_findings_filtered_with_identity_policy(
        &self,
        filter: &FindingListFilter,
        policy: IdentityFoldPolicy,
    ) -> Result<FindingListReport> {
        collect_filtered_findings(self, self.policy_projected_findings(policy)?, filter)
    }

    /// Full-ledger fetch under the policy the caller resolved.
    ///
    /// An export is a reader of the same ledger an operator reviewed, so it
    /// must fold the same way. [`Self::list_all_findings`] projects the
    /// compatibility generation only, which collapses repeated observations of
    /// one durable finding but keeps two same-issue rows from different
    /// channels apart. Exporting that set published a finding count the Review
    /// ledger denied on the same screen, and assigned export aliases by
    /// positions the shell's own alias resolution never produced.
    pub fn list_all_findings_with_identity_policy(
        &self,
        policy: IdentityFoldPolicy,
    ) -> Result<Vec<Finding>> {
        self.policy_projected_findings(policy)
    }

    pub fn list_relevant_findings_with_identity_policy(
        &self,
        policy: IdentityFoldPolicy,
    ) -> Result<Vec<Finding>> {
        let findings = self.policy_projected_findings(policy)?;
        let stable_fps = findings.iter().map(finding_stable_key).collect::<Vec<_>>();
        let statuses = self.current_statuses_for(&stable_fps)?;
        Ok(findings
            .into_iter()
            .filter(|finding| finding_is_relevant_with_statuses(finding, &statuses))
            .collect())
    }

    fn policy_projected_findings(&self, policy: IdentityFoldPolicy) -> Result<Vec<Finding>> {
        let generations = self.finding_generations_in_observation_order()?;
        let mut projected = project_finding_generations(generations, policy);
        projected.sort_by(super::v3_finding_reads::finding_list_order);
        self.hydrate_v3_findings(projected)
    }

    pub(in crate::findings) fn matching_findings_for_page(
        &self,
        filter: &FindingListFilter,
        policy: IdentityFoldPolicy,
    ) -> Result<FindingListReport> {
        let mut complete_filter = filter.clone();
        complete_filter.limit = usize::MAX;
        collect_filtered_findings(
            self,
            self.policy_projected_findings(policy)?,
            &complete_filter,
        )
    }

    pub fn finding_for_alias_with_identity_policy(
        &self,
        alias: &str,
        policy: IdentityFoldPolicy,
    ) -> Result<Option<Finding>> {
        let findings = self.policy_projected_findings(policy)?;
        Ok(crate::findings::resolve_finding_alias(&findings, alias))
    }
}

fn collect_filtered_findings(
    store: &FindingStore,
    rows: Vec<Finding>,
    filter: &FindingListFilter,
) -> Result<FindingListReport> {
    anyhow::ensure!(
        filter.batch_id.is_none() && !filter.has_scope_filter(),
        "Study or scope membership needs the workspace findings reader; use findings:list"
    );
    // Aliases are positional over the sorted whole ledger, so they must be
    // assigned here — before filtering — and travel with the kept rows.
    let alias_by_row = ledger_aliases_by_row_index(&rows);
    let mut count = 0;
    let mut findings = Vec::new();
    let mut aliases = Vec::new();
    let review_cache = store.latest_review_decisions_for_findings(&rows, false)?;
    let human_review_cache = human_decisions_for_filter(store, &rows, filter)?;
    let stable_fps = rows.iter().map(finding_stable_key).collect::<Vec<_>>();
    let lifecycle_cache = store.current_statuses_for(&stable_fps)?;
    for (index, row) in rows.into_iter().enumerate() {
        let kept_before = findings.len();
        count += push_matching_finding(
            &review_cache,
            &human_review_cache,
            &lifecycle_cache,
            &mut findings,
            row,
            filter,
        ) as usize;
        if findings.len() > kept_before {
            aliases.push(alias_by_row[index].clone());
        }
    }
    let review_decisions = review_decisions_by_fingerprint(&findings, &review_cache);
    Ok(FindingListReport {
        review_decisions,
        count,
        findings,
        aliases,
    })
}

fn human_decisions_for_filter(
    store: &FindingStore,
    rows: &[Finding],
    filter: &FindingListFilter,
) -> Result<std::collections::BTreeMap<String, ReviewDecision>> {
    filter
        .has_derived_triage_state_filter()
        .then(|| store.latest_review_decisions_for_findings(rows, true))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn review_decisions_by_fingerprint(
    findings: &[Finding],
    cache: &std::collections::BTreeMap<String, ReviewDecision>,
) -> std::collections::BTreeMap<String, ReviewDecision> {
    findings
        .iter()
        .filter_map(|finding| {
            let decision = cache.get(&review_cache_key(finding)?)?;
            Some((finding.fingerprint.clone(), decision.clone()))
        })
        .collect()
}

fn ledger_aliases_by_row_index(rows: &[Finding]) -> Vec<String> {
    let mut by_row = vec![String::new(); rows.len()];
    for (alias, row_index) in crate::findings::sorted_finding_alias_indices(rows) {
        by_row[row_index] = alias;
    }
    by_row
}

fn push_matching_finding(
    review_cache: &std::collections::BTreeMap<String, ReviewDecision>,
    human_review_cache: &std::collections::BTreeMap<String, ReviewDecision>,
    lifecycle_cache: &std::collections::BTreeMap<String, String>,
    findings: &mut Vec<Finding>,
    finding: Finding,
    filter: &FindingListFilter,
) -> bool {
    let cache_key = review_cache_key(&finding);
    let review_decision = cache_key.as_ref().and_then(|key| review_cache.get(key));
    if !filter.matches_with_review_decision(&finding, review_decision) {
        return false;
    }
    if !matches_derived_filter(
        human_review_cache,
        lifecycle_cache,
        &finding,
        cache_key.as_deref(),
        filter,
    ) {
        return false;
    }
    if findings.len() < filter.limit {
        findings.push(finding);
    }
    true
}

fn matches_derived_filter(
    human_reviews: &std::collections::BTreeMap<String, ReviewDecision>,
    lifecycles: &std::collections::BTreeMap<String, String>,
    finding: &Finding,
    cache_key: Option<&str>,
    filter: &FindingListFilter,
) -> bool {
    if !filter.has_derived_triage_state_filter() {
        return true;
    }
    let lifecycle = lifecycles
        .get(&finding_stable_key(finding))
        .map(|status| StableLifecycleStatus::from_current_status(status))
        .unwrap_or(StableLifecycleStatus::Open);
    // Human review wins over later automated re-triage.
    let human_decision = cache_key.and_then(|key| human_reviews.get(key));
    filter.matches_triage_lifecycle(&derive_triage_state(lifecycle, human_decision))
}

fn review_cache_key(finding: &Finding) -> Option<String> {
    finding
        .identity_id
        .as_ref()
        .map(|identity_id| format!("identity:{identity_id}"))
        .or_else(|| finding.id.map(|finding_id| format!("finding:{finding_id}")))
}

fn finding_stable_key(finding: &Finding) -> String {
    finding
        .identity_id
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone())
}

fn finding_is_relevant_with_statuses(
    finding: &Finding,
    statuses: &std::collections::BTreeMap<String, String>,
) -> bool {
    !finding.suppressed
        && statuses
            .get(&finding_stable_key(finding))
            .is_none_or(|status| matches!(status.as_str(), "open" | "stale"))
}

#[cfg(test)]
mod full_ledger_fetch_tests {
    use crate::findings::{
        Finding, FindingIdentityBasis, FindingListFilter, FindingStore, IdentityFoldPolicy,
    };
    use crate::Severity;

    fn insert_strong_generation(
        store: &FindingStore,
        target: &std::path::Path,
        run_id: &str,
        fingerprint: &str,
        dedup_key: &str,
        tool: &str,
    ) {
        store.record_run_started(run_id, target, "running").unwrap();
        let mut finding = Finding::new_tool(
            tool,
            "CWE-78",
            "src/app.rs",
            1,
            Some(1),
            Severity::High,
            "command execution",
        );
        finding.fingerprint = fingerprint.to_string();
        finding.dedup_key = Some(dedup_key.to_string());
        finding.symbol_locator = Some("app::execute".to_string());
        store.insert_finding(run_id, &finding).unwrap();
    }

    #[test]
    fn list_all_findings_sees_past_the_presentation_clamp() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open(tmp.path().join("findings.db")).unwrap();
        store
            .with_run_lifecycle("run-clamp-test", tmp.path(), || {
                for index in 0..501usize {
                    let finding = Finding::new_tool(
                        "clamp-test",
                        "clamp/rule",
                        &format!("src/f{index}.c"),
                        1,
                        None,
                        Severity::Low,
                        &format!("clamp row {index}"),
                    );
                    store.insert_finding("run-clamp-test", &finding)?;
                }
                Ok(((), 501usize))
            })
            .unwrap();

        assert_eq!(store.list_findings(1000).unwrap().len(), 500);
        let all = store.list_all_findings().unwrap();
        assert_eq!(all.len(), 501);
        // Alias indices must be assignable across the whole ledger.
        let aliases = crate::findings::sorted_finding_aliases(&all);
        assert_eq!(aliases.len(), 501);
    }

    /// A filtered list must show the same alias `kz finding F-nnnn`
    /// resolves — ledger-positional, not subset-positional. A severity
    /// filter that drops earlier-aliased rows is the regression trap.
    #[test]
    fn filtered_list_carries_ledger_stable_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open(tmp.path().join("findings.db")).unwrap();
        store
            .with_run_lifecycle("run-alias-test", tmp.path(), || {
                for (index, severity) in [Severity::High, Severity::High, Severity::Low]
                    .iter()
                    .enumerate()
                {
                    let finding = Finding::new_tool(
                        "alias-test",
                        "alias/rule",
                        &format!("src/f{index}.c"),
                        1,
                        None,
                        *severity,
                        &format!("alias row {index}"),
                    );
                    store.insert_finding("run-alias-test", &finding)?;
                }
                Ok(((), 3usize))
            })
            .unwrap();

        let filter = crate::findings::FindingListFilter::from_tool_input(
            &serde_json::json!({"severity": ["low"]}),
        )
        .unwrap();
        let report = store.list_findings_filtered(&filter).unwrap();

        assert_eq!(report.findings.len(), 1);
        let all = store.list_all_findings().unwrap();
        let ledger_alias =
            crate::findings::stable_finding_alias(&all, &report.findings[0].fingerprint).unwrap();
        // The low row sorts after both highs, so subset-positional aliasing
        // would mislabel it F-0001.
        assert_eq!(ledger_alias, "F-0003");
        assert_eq!(report.aliases, vec![ledger_alias]);
        assert!(report.output().contains("F-0003"));
        assert!(!report.output().contains("F-0001"));
    }

    #[test]
    fn policy_projection_folds_only_when_the_selected_policy_allows_it() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::fs::write(tmp.path().join("src/app.rs"), "execute(input);\n").unwrap();
        let store = FindingStore::open(tmp.path().join("findings.db")).unwrap();
        insert_strong_generation(
            &store,
            tmp.path(),
            "strong-a",
            "producer-a",
            "dedup-a",
            "semgrep",
        );
        insert_strong_generation(
            &store,
            tmp.path(),
            "strong-b",
            "producer-b",
            "dedup-b",
            "codeql",
        );
        let filter = FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT);

        let legacy = store
            .list_findings_filtered_with_identity_policy(&filter, IdentityFoldPolicy::Legacy)
            .unwrap();
        let safe = store
            .list_findings_filtered_with_identity_policy(&filter, IdentityFoldPolicy::Safe)
            .unwrap();

        assert_eq!(
            (legacy.count, legacy.findings.len(), legacy.aliases.len()),
            (2, 2, 2)
        );
        assert_eq!(
            (safe.count, safe.findings.len(), safe.aliases.len()),
            (1, 1, 1)
        );
        assert_eq!(safe.findings[0].sources.len(), 2);
        assert_eq!(safe.findings[0].corroboration_count, 2);
    }

    #[test]
    fn safe_projection_preserves_distinct_file_fallback_signatures() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open(tmp.path().join("findings.db")).unwrap();
        for (run_id, fingerprint, line, signature) in [
            ("run-fallback-a", "producer-a", 10, "src/db.rs:10:CWE-89"),
            (
                "run-fallback-match",
                "producer-match",
                10,
                "src/db.rs:10:CWE-89",
            ),
            ("run-fallback-b", "producer-b", 90, "src/db.rs:90:CWE-89"),
        ] {
            store
                .record_run_started(run_id, tmp.path(), "running")
                .unwrap();
            let mut finding = Finding::new_tool(
                "semgrep",
                "CWE-89",
                "src/db.rs",
                line,
                Some(line),
                Severity::High,
                "SQL injection",
            );
            finding.fingerprint = fingerprint.to_string();
            finding.source_signature = Some(signature.to_string());
            store.insert_finding(run_id, &finding).unwrap();
        }

        let generations = store.list_emitted_finding_generations().unwrap();
        assert_eq!(generations.len(), 3);
        assert!(generations
            .windows(2)
            .all(|rows| rows[0].identity_id == rows[1].identity_id));
        assert!(generations
            .iter()
            .any(|finding| finding.identity_basis == Some(FindingIdentityBasis::FileFallback)));
        assert!(generations
            .iter()
            .any(|finding| finding.effective_identity_basis().is_strong()));
        let filter = FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT);
        let projected = store
            .list_findings_filtered_with_identity_policy(&filter, IdentityFoldPolicy::Safe)
            .unwrap()
            .findings;
        assert_eq!(projected.len(), 2);
        assert_ne!(projected[0].source_signature, projected[1].source_signature);
    }

    fn insert_fallback_observation(
        store: &FindingStore,
        target: &std::path::Path,
        run_id: &str,
        tool: &str,
        line: u32,
        dedup_key: &str,
    ) {
        store
            .record_run_started(run_id, target, "completed")
            .unwrap();
        let mut finding = Finding::new_tool(
            tool,
            "CWE-89",
            "src/db.rs",
            line,
            Some(line),
            Severity::High,
            "SQL injection",
        );
        finding.fingerprint = format!("producer-{tool}-{line}");
        finding.dedup_key = Some(dedup_key.to_string());
        finding.source_signature = Some(format!("src/db.rs:{line}:CWE-89"));
        store.insert_finding(run_id, &finding).unwrap();
    }

    /// The compatibility projection (`list_findings`) applies the same rule
    /// as the Rust safe fold: a finding first minted with a weak file-fallback
    /// identity joins that identity once a later run rediscovers it through
    /// the shared dedup key, while a fallback nothing corroborates keeps its
    /// own row.
    #[test]
    fn compatibility_projection_folds_a_weak_observation_only_into_corroborated_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open(tmp.path().join("findings.db")).unwrap();
        insert_fallback_observation(
            &store,
            tmp.path(),
            "run-a",
            "semgrep",
            10,
            "src/db.rs:CWE-89",
        );
        insert_fallback_observation(
            &store,
            tmp.path(),
            "run-b",
            "codeql",
            12,
            "src/db.rs:CWE-89",
        );
        insert_fallback_observation(
            &store,
            tmp.path(),
            "run-c",
            "semgrep",
            90,
            "src/db.rs:other",
        );

        let generations = store.list_emitted_finding_generations().unwrap();
        assert_eq!(generations.len(), 3);
        let strong = generations
            .iter()
            .filter(|finding| finding.effective_identity_basis().is_strong())
            .count();
        assert_eq!(
            strong, 1,
            "only the cross-run rediscovery carries a strong basis"
        );

        let projected = store.list_findings(10).unwrap();
        let mut tools = projected
            .iter()
            .map(|finding| finding.tool.as_str())
            .collect::<Vec<_>>();
        tools.sort_unstable();
        assert_eq!(
            projected.len(),
            2,
            "corroborated pair folds; lone fallback stays"
        );
        assert_eq!(tools, vec!["codeql", "semgrep"]);
        let folded = projected
            .iter()
            .find(|finding| finding.tool == "codeql")
            .unwrap();
        assert_eq!(folded.sources.len(), 2);
        assert_eq!(folded.corroboration_count, 2);
    }

    #[test]
    fn safe_projection_never_folds_attack_chains() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::fs::write(tmp.path().join("src/app.rs"), "execute(input);\n").unwrap();
        let store = FindingStore::open(tmp.path().join("findings.db")).unwrap();
        insert_strong_generation(
            &store,
            tmp.path(),
            "chain-a",
            "chain-a",
            "dedup-a",
            "chains",
        );
        insert_strong_generation(
            &store,
            tmp.path(),
            "chain-b",
            "chain-b",
            "dedup-b",
            "chains",
        );
        let filter = FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT);

        let projected = store
            .list_findings_filtered_with_identity_policy(&filter, IdentityFoldPolicy::Safe)
            .unwrap();

        assert_eq!(projected.count, 2);
        assert_eq!(projected.findings.len(), 2);
    }
}
