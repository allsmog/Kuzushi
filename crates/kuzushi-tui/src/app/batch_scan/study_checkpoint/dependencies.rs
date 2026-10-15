use super::recovery::{RecoveryOutcome, RestoreDependencies};
use super::*;

fn read_accounting(
    target: &std::path::Path,
    investigation_id: &str,
) -> anyhow::Result<Option<kuzushi_core::allowance::AllowanceSnapshot>> {
    let db = kuzushi_core::WorkspaceTarget::new(target)?.findings_db_path();
    match kuzushi_core::SpendLimiter::read_allowance_snapshot(&db, investigation_id) {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if matches!(
                error.downcast_ref::<kuzushi_core::allowance::AllowanceError>(),
                Some(kuzushi_core::allowance::AllowanceError::NotApproved(_))
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn start_selected(
    target: PathBuf,
    saved: RecoveredStudyDraft,
) -> anyhow::Result<Receiver<Result<RecoveryOutcome, String>>> {
    let (send, receive) = mpsc::channel();
    std::thread::Builder::new()
        .name("study-draft-validation".into())
        .spawn(move || {
            let result = validate_dependencies(&target, &saved)
                .map(|dependencies| RecoveryOutcome::Selected {
                    saved,
                    dependencies,
                })
                .map_err(|error| error.to_string());
            let _ = send.send(result);
        })?;
    Ok(receive)
}

fn validate_dependencies(
    target: &std::path::Path,
    saved: &RecoveredStudyDraft,
) -> anyhow::Result<RestoreDependencies> {
    let snapshot = saved
        .record
        .snapshot
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Study checkpoint is already resolved"))?;
    validate_contexts(target, snapshot)?;
    let brief = snapshot
        .brief_ref
        .as_ref()
        .map(|r| kuzushi_core::capabilities::campaign::load_brief(target, r))
        .transpose()?;
    let brief_draft = load_brief_draft(target, snapshot)?;
    Ok(RestoreDependencies {
        brief,
        brief_draft,
        accounting: read_accounting(target, &snapshot.investigation_id)
            .map_err(|error| error.to_string()),
    })
}

fn validate_contexts(
    target: &std::path::Path,
    snapshot: &StudyCheckpointSnapshot,
) -> anyhow::Result<()> {
    for case in &snapshot.cases {
        validate_context(target, &case.threat_model_ref)?;
    }
    if let Some(value) = snapshot.scan_input.get("threatModelRef") {
        validate_context(target, value)?;
    }
    if let Some(scope) = &snapshot.scope {
        validate_scope(target, scope)?;
    }
    Ok(())
}

fn validate_scope(target: &std::path::Path, scope: &ScopeCheckpoint) -> anyhow::Result<()> {
    let workspace = kuzushi_core::WorkspaceTarget::new(target)?;
    kuzushi_core::workspace::load_scan_scope_proposal(&workspace, &scope.proposal_ref)?;
    for case in &scope.cases {
        if let Some(value) = &case.threat_model_ref {
            validate_context(target, value)?;
        }
    }
    Ok(())
}

fn validate_context(target: &std::path::Path, value: &serde_json::Value) -> anyhow::Result<()> {
    if value.is_null() {
        return Ok(());
    }
    let reference: kuzushi_core::ThreatModelRef = serde_json::from_value(value.clone())?;
    let loaded = kuzushi_core::capabilities::threat_model::load_threat_model_revision(
        target,
        &reference.model_id,
        Some(&reference.revision_id),
    )?;
    anyhow::ensure!(
        loaded.model_ref == reference,
        "Saved context failed immutable object verification"
    );
    Ok(())
}

fn load_brief_draft(
    target: &std::path::Path,
    snapshot: &StudyCheckpointSnapshot,
) -> anyhow::Result<Option<crate::app::BriefEditor>> {
    let Some(draft) = &snapshot.brief_draft else {
        return Ok(None);
    };
    let base = draft
        .base_ref
        .as_ref()
        .map(|r| kuzushi_core::capabilities::campaign::load_brief(target, r))
        .transpose()?;
    super::brief::restore(draft, base).map(Some)
}
