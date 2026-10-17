use super::*;
use crate::run_lifecycle::RunObservationHandle;
use crate::ToolExecutionContext;

/// Where a tool's findings commit and which run observes that commit.
#[derive(Clone)]
pub(crate) struct ToolFindingsSink<'a> {
    pub(crate) run_id: String,
    pub(crate) workspace: Option<&'a WorkspaceTarget>,
    pub(crate) store: Option<&'a FindingStore>,
    pub(crate) observation: Option<RunObservationHandle>,
}

impl<'a> ToolFindingsSink<'a> {
    pub(crate) fn for_context(ctx: &ToolExecutionContext<'a>) -> Self {
        Self {
            run_id: ctx.finding_run_id(),
            workspace: ctx.workspace,
            store: ctx.findings_store,
            observation: ctx.run_observation(),
        }
    }
}

/// Persist a tool's findings into the context's store and commit the typed
/// finding delta on the dispatching run, so receipts measure what changed.
pub(crate) fn persist_tool_findings(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    findings: &[Finding],
) -> Result<Option<GenericPersistedRun>> {
    persist_tool_findings_to(ToolFindingsSink::for_context(ctx), target, findings)
}

pub(crate) fn persist_tool_findings_to(
    sink: ToolFindingsSink<'_>,
    target: &Path,
    findings: &[Finding],
) -> Result<Option<GenericPersistedRun>> {
    persist_tool_findings_to_with_status(
        sink,
        target,
        findings,
        crate::run_lifecycle::RunItemStatus::Completed,
    )
}

pub(crate) fn persist_tool_findings_to_with_status(
    sink: ToolFindingsSink<'_>,
    target: &Path,
    findings: &[Finding],
    status: crate::run_lifecycle::RunItemStatus,
) -> Result<Option<GenericPersistedRun>> {
    let (Some(workspace), Some(store)) = (sink.workspace, sink.store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    crate::findings::commit_observed_findings_with_status(
        store,
        sink.observation.as_ref(),
        &sink.run_id,
        target,
        findings,
        status,
    )?;
    Ok(Some(GenericPersistedRun {
        run_id: sink.run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_artifacts::TraceHandle;
    use crate::run_lifecycle::{load_run_projection, FindingDeltaSummary};

    #[test]
    fn findings_use_the_canonical_execution_run_id() {
        let target = tempfile::tempdir().unwrap();
        let (workspace, store) = open_store(target.path());

        let persisted = persist_observed(
            target.path(),
            &workspace,
            &store,
            "run-canonical",
            &[test_finding("secret-scan/test")],
        );

        assert_eq!(persisted.run_id, "run-canonical");
        assert_eq!(
            store
                .list_findings_for_scan_id("run-canonical")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn persisted_findings_commit_a_typed_delta_on_the_run() {
        let target = tempfile::tempdir().unwrap();
        let (workspace, store) = open_store(target.path());
        let known = test_finding("secret-scan/known");
        persist_observed(
            target.path(),
            &workspace,
            &store,
            "run-first",
            &[known.clone()],
        );

        let fresh = [known, test_finding("secret-scan/fresh")];
        persist_observed(target.path(), &workspace, &store, "run-second", &fresh);

        let delta = only_delta(target.path(), "run-second");
        assert_eq!((delta.added, delta.updated, delta.removed), (1, 1, 0));
        assert!(!delta.store_watermark.as_str().contains("unavailable"));
        assert_eq!(delta.finding_id_samples.len(), 2);
    }

    /// The delta a receipt carries has to name the findings the ledger holds.
    /// Two channels reporting one issue commit one finding, and counting the
    /// observations instead is what made the RESULT READY banner read
    /// `findings +27` over a Review ledger of 25. Issue #172, 2026-10-05.
    #[test]
    fn a_folded_observation_pair_commits_one_finding_not_two() {
        let target = tempfile::tempdir().unwrap();
        let (workspace, store) = open_store(target.path());
        // One issue at one location, reported by two channels: the shared
        // file/line/CWE gives them one dedup key and one source signature, so
        // the insertion merges them.
        let semgrep = Finding::new_tool(
            "semgrep",
            "java.injection.tainted-system-call",
            "src/foo.c",
            42,
            Some(42),
            Severity::Medium,
            "user-controlled exec, CWE-78",
        );
        let full_mode = Finding::new_tool(
            "full-mode-multi",
            "full-mode-multi/cwe-78",
            "src/foo.c",
            42,
            Some(42),
            Severity::High,
            "exec with attacker-controlled argv, CWE-78",
        );
        assert_eq!(semgrep.dedup_key, full_mode.dedup_key);
        assert_ne!(semgrep.fingerprint, full_mode.fingerprint);

        persist_observed(
            target.path(),
            &workspace,
            &store,
            "run-folded",
            &[semgrep, full_mode],
        );

        let ledger = store.list_findings_for_scan_id("run-folded").unwrap();
        assert_eq!(ledger.len(), 1, "the pair merged into one finding");
        let delta = only_delta(target.path(), "run-folded");
        assert_eq!((delta.added, delta.updated, delta.removed), (1, 0, 0));
    }

    #[test]
    fn a_clean_run_still_commits_a_zero_delta() {
        let target = tempfile::tempdir().unwrap();
        let (workspace, store) = open_store(target.path());

        persist_observed(target.path(), &workspace, &store, "run-clean", &[]);

        let delta = only_delta(target.path(), "run-clean");
        assert_eq!((delta.added, delta.updated), (0, 0));
    }

    fn open_store(target: &Path) -> (WorkspaceTarget, FindingStore) {
        let workspace = WorkspaceTarget::new(target).unwrap();
        workspace.ensure_state_dir().unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        (workspace, store)
    }

    fn persist_observed(
        target: &Path,
        workspace: &WorkspaceTarget,
        store: &FindingStore,
        run_id: &str,
        findings: &[Finding],
    ) -> GenericPersistedRun {
        let config = crate::V2Config::default();
        // Dropping the trace joins the run-item writer so projections see it.
        let trace =
            TraceHandle::observed_jsonl_with_delivery_subscribers(target, run_id, None, None, None)
                .unwrap();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(workspace),
            findings_store: Some(store),
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };
        persist_tool_findings(&ctx, target, findings)
            .unwrap()
            .unwrap()
    }

    fn only_delta(target: &Path, run_id: &str) -> FindingDeltaSummary {
        let projection = load_run_projection(target, run_id).unwrap().projection;
        assert_eq!(projection.finding_deltas.len(), 1);
        projection.finding_deltas.into_iter().next().unwrap()
    }

    fn test_finding(rule_id: &str) -> Finding {
        Finding::new_tool(
            "secret-scan",
            rule_id,
            "src/config.rs",
            1,
            None,
            Severity::High,
            "test finding",
        )
    }
}

pub(crate) fn render_generic_findings_output(
    tool_name: &str,
    target: &Path,
    findings: &[Finding],
    persisted: &Option<GenericPersistedRun>,
) -> String {
    let mut lines = vec![format!(
        "{tool_name} complete for {}\n  Findings: {}",
        target.display(),
        findings.len()
    )];
    if let Some(persisted) = persisted {
        lines.push(format!(
            "  Persisted run: {} ({})",
            persisted.run_id, persisted.findings_db
        ));
    }
    if !findings.is_empty() {
        lines.push(String::new());
        lines.push("Top findings:".to_string());
        for finding in findings.iter().take(10) {
            lines.push(format!(
                "  - {} - {} - {}:{}",
                finding.severity.as_str(),
                finding.rule_id,
                finding.file_path,
                finding.start_line
            ));
        }
    }
    lines.join("\n")
}
