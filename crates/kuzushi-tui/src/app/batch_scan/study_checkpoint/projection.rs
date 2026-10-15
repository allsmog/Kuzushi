use super::super::context_matrix::ContextCaseNameEdit;
use super::super::number_edit::BatchNumberEdit;
use super::*;
use kuzushi_core::capabilities::campaign::ScopeStudyDraft;

pub(super) fn capture(
    config: &BatchScanConfig,
    scan_input: serde_json::Value,
) -> StudyCheckpointSnapshot {
    let matrix = &config.study.matrix;
    StudyCheckpointSnapshot {
        investigation_id: config.study.investigation_id.clone(),
        trials: config.trials,
        requested_workers: config.requested_workers,
        scan_input,
        cases: matrix.cases.clone(),
        baseline_case_id: matrix.baseline_case_id.clone(),
        matrix_cursor: matrix.cursor,
        matrix_open: matrix.open,
        form_cursor: config.cursor,
        detail_scroll: config.detail_scroll,
        name_edit: capture_name(config),
        number_edit: capture_number(config),
        max_provider_calls: config.study.max_provider_calls,
        protected_review_calls: config.study.protected_review_calls,
        max_job_attempts: config.study.max_job_attempts,
        prior_run_id: config.prior_run_id.clone(),
        prior_campaign_id: config.prior_campaign_id.clone(),
        context_baseline_run_id: config.study.context_baseline_run_id.clone(),
        brief_ref: config.study.brief.as_ref().map(|b| b.reference.clone()),
        brief_draft: None,
        scope: config.study.scope_draft.as_ref().map(|s| ScopeCheckpoint {
            proposal_ref: s.proposal_ref.clone(),
            cases: s.cases.clone(),
            labels: config.scope_context.labels.clone(),
        }),
        origin_hashes: config.checkpoint_origins.clone(),
    }
}

fn capture_name(config: &BatchScanConfig) -> Option<CaseNameCheckpoint> {
    let edit = config.study.matrix.name_edit.as_ref()?;
    config
        .study
        .matrix
        .cases
        .iter()
        .find(|case| case.id == edit.case_id)?;
    Some(CaseNameCheckpoint {
        case_id: edit.case_id.clone(),
        field: text(&edit.field),
        open: edit.open,
    })
}

fn capture_number(config: &BatchScanConfig) -> Option<NumberCheckpoint> {
    let edit = config.number_edit.as_ref()?;
    let row = numeric_rows()
        .into_iter()
        .find(|(_, row)| *row == edit.row)?
        .0;
    Some(NumberCheckpoint {
        row: row.into(),
        field: text(&edit.field),
    })
}

fn text(field: &FieldEditor) -> DraftText {
    DraftText {
        text: field.text().into(),
        cursor: field.cursor(),
    }
}

pub(super) fn restore(
    config: &mut BatchScanConfig,
    snapshot: &StudyCheckpointSnapshot,
) -> anyhow::Result<()> {
    config.study.invalidate_plan();
    config.study.allowance = None;
    config.study.investigation_id = snapshot.investigation_id.clone();
    config.study.scan_input = Some(snapshot.scan_input.clone());
    config.trials = snapshot.trials;
    config.requested_workers = snapshot.requested_workers;
    config.study.matrix.cases = snapshot.cases.clone();
    config.study.matrix.baseline_case_id = snapshot.baseline_case_id.clone();
    config.study.matrix.cursor = snapshot.matrix_cursor;
    config.study.matrix.open = snapshot.matrix_open;
    config.study.matrix.name_edit = restore_name(&snapshot.name_edit)?;
    config.number_edit = restore_number(&snapshot.number_edit)?;
    restore_resource_choices(config, snapshot);
    config.cursor = snapshot.form_cursor;
    config.detail_scroll = snapshot.detail_scroll;
    config.study.scope_draft = snapshot.scope.as_ref().map(|s| ScopeStudyDraft {
        proposal_ref: s.proposal_ref.clone(),
        cases: s.cases.clone(),
    });
    config.scope_context.labels = snapshot
        .scope
        .as_ref()
        .map_or_else(BTreeMap::new, |s| s.labels.clone());
    config.checkpoint_origins = snapshot.origin_hashes.clone();
    config.draft_recovery = Default::default();
    config.notice = Some("Study choices recovered. Prepare a fresh plan, inspect source and context, then approve its allowance. No jobs started.".into());
    Ok(())
}

fn restore_resource_choices(config: &mut BatchScanConfig, snapshot: &StudyCheckpointSnapshot) {
    config.study.max_provider_calls = snapshot.max_provider_calls;
    config.study.protected_review_calls = snapshot.protected_review_calls;
    config.study.max_job_attempts = snapshot.max_job_attempts;
    config.prior_run_id = snapshot.prior_run_id.clone();
    config.prior_campaign_id = snapshot.prior_campaign_id.clone();
    config.study.context_baseline_run_id = snapshot.context_baseline_run_id.clone();
}

fn restore_name(edit: &Option<CaseNameCheckpoint>) -> anyhow::Result<Option<ContextCaseNameEdit>> {
    edit.as_ref()
        .map(|edit| {
            Ok(ContextCaseNameEdit {
                case_id: edit.case_id.clone(),
                field: editor(&edit.field)?,
                error: None,
                open: edit.open,
            })
        })
        .transpose()
}

fn restore_number(edit: &Option<NumberCheckpoint>) -> anyhow::Result<Option<BatchNumberEdit>> {
    edit.as_ref()
        .map(|edit| {
            let row = numeric_rows()
                .into_iter()
                .find(|(name, _)| *name == edit.row)
                .ok_or_else(|| anyhow::anyhow!("Saved numeric field is unavailable"))?
                .1;
            Ok(BatchNumberEdit {
                row,
                field: editor(&edit.field)?,
                error: None,
            })
        })
        .transpose()
}

fn editor(field: &DraftText) -> anyhow::Result<FieldEditor> {
    let mut editor = FieldEditor::new(&field.text);
    editor.restore_cursor(field.cursor)?;
    Ok(editor)
}

fn numeric_rows() -> [(&'static str, BatchScanConfigRow); 6] {
    use BatchScanConfigRow::*;
    [
        ("passes", Trials),
        ("workers", Workers),
        ("calls", ProviderCalls),
        ("review", ReviewCalls),
        ("attempts", Attempts),
        ("case-passes", CasePasses),
    ]
}
