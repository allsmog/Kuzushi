use super::*;
use kuzushi_core::capabilities::campaign::ScopeStudyDraft;

impl StudyCheckpointRecord {
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == 1 && self.target.is_absolute(),
            "Unsupported study checkpoint or target"
        );
        validate_uuid(&self.record_id)?;
        validate_uuid(&self.session_id)?;
        validate_hashes(&self.resolved_hashes)?;
        if let Some(snapshot) = &self.snapshot {
            snapshot.validate()?;
        }
        anyhow::ensure!(
            serde_json::to_vec(self)?.len() <= 8 * 1024 * 1024,
            "Study checkpoint exceeds its file limit"
        );
        Ok(())
    }
}

impl StudyCheckpointSnapshot {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.cases.len() <= MAX_CONTEXT_CASES,
            "Too many checkpointed context cases"
        );
        let mut ids = BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            anyhow::ensure!(ids.insert(&case.id), "Duplicate checkpointed case id");
        }
        anyhow::ensure!(
            self.baseline_case_id
                .as_ref()
                .is_none_or(|id| ids.contains(id)),
            "Saved baseline is outside its cases"
        );
        validate_selections(self)?;
        validate_editors(self, &ids)?;
        if let Some(scope) = &self.scope {
            validate_scope(scope)?;
        }
        validate_hashes(&self.origin_hashes)
    }
}

fn validate_editors(
    snapshot: &StudyCheckpointSnapshot,
    ids: &BTreeSet<&String>,
) -> anyhow::Result<()> {
    if let Some(edit) = &snapshot.name_edit {
        anyhow::ensure!(
            ids.contains(&edit.case_id),
            "Saved name belongs to a removed case"
        );
        validate_text(&edit.field)?;
    }
    if let Some(edit) = &snapshot.number_edit {
        validate_text(&edit.field)?;
    }
    if let Some(draft) = &snapshot.brief_draft {
        draft.validate()?;
    }
    Ok(())
}

fn validate_selections(snapshot: &StudyCheckpointSnapshot) -> anyhow::Result<()> {
    anyhow::ensure!(
        snapshot.scan_input.is_object(),
        "Saved discovery input is not an object"
    );
    anyhow::ensure!(
        (2..=50).contains(&snapshot.trials) && (1..=8).contains(&snapshot.requested_workers),
        "Saved passes or workers are out of range"
    );
    anyhow::ensure!(
        (1..=10).contains(&snapshot.max_job_attempts),
        "Saved attempt limit is out of range"
    );
    anyhow::ensure!(
        snapshot.investigation_id.len() <= 128
            && !snapshot.investigation_id.is_empty()
            && snapshot
                .investigation_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)),
        "Saved investigation id is invalid"
    );
    anyhow::ensure!(
        snapshot
            .max_provider_calls
            .is_none_or(|n| (1..=1_000_000).contains(&n))
            && snapshot
                .protected_review_calls
                .is_none_or(|n| n <= 1_000_000),
        "Saved call limit is out of range"
    );
    anyhow::ensure!(
        snapshot.form_cursor < 12
            && snapshot.matrix_cursor <= 8
            && snapshot.detail_scroll <= 8 * 1024 * 1024,
        "Saved study cursor is out of range"
    );
    Ok(())
}

fn validate_scope(scope: &ScopeCheckpoint) -> anyhow::Result<()> {
    ScopeStudyDraft {
        proposal_ref: scope.proposal_ref.clone(),
        cases: scope.cases.clone(),
    }
    .validate()?;
    anyhow::ensure!(scope.labels.len() <= 9, "Too many scope labels");
    for label in scope.labels.values() {
        anyhow::ensure!(
            label.len() <= 256 && !label.chars().any(char::is_control),
            "Invalid scope label"
        );
    }
    Ok(())
}

fn validate_uuid(id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        uuid::Uuid::parse_str(id)?.to_string() == id,
        "Checkpoint id is not canonical"
    );
    Ok(())
}

fn validate_text(text: &DraftText) -> anyhow::Result<()> {
    anyhow::ensure!(
        text.text.len() <= 2048 && !text.text.contains('\0'),
        "Saved field exceeds its text limit"
    );
    anyhow::ensure!(
        text.cursor <= text.text.chars().count(),
        "Saved cursor is outside its field"
    );
    Ok(())
}

fn validate_hashes(hashes: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        hashes.len() <= 32,
        "Study draft recovery chain exceeds its limit"
    );
    for hash in hashes {
        anyhow::ensure!(
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Invalid study checkpoint hash"
        );
    }
    Ok(())
}
