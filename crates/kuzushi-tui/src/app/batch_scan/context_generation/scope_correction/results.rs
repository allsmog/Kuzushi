use super::*;

impl ShellApp {
    pub(crate) fn cache_scope_correction_result(&mut self, tool: &str, data: &Value) -> bool {
        if !self.matches_own_pending_correction(tool, data) {
            return false;
        }
        let generation = self
            .scope_correction_generation_mut()
            .expect("matched correction generation");
        let state = generation
            .scope_correction
            .as_mut()
            .expect("matched correction editor");
        match correction_result(data, state) {
            Ok(review) => {
                generation.generated_scopes = Some(review);
                state.pending_draft_hash = None;
                state.editing = false;
                state.original = state.editor.text().to_owned();
                state.notice = None;
                generation.show_rejected = false;
                generation.scroll = 0;
            }
            Err(error) => {
                state.pending_draft_hash = None;
                state.notice = Some(error.to_string());
            }
        }
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.notice = None;
        }
        true
    }

    fn matches_own_pending_correction(&self, tool: &str, data: &Value) -> bool {
        if tool != "pack:scopes" {
            return false;
        }
        self.context_generation()
            .and_then(|generation| generation.scope_correction.as_ref())
            .filter(|state| state.pending_draft_hash.is_some())
            .is_some_and(|state| matches_pending_correction(data, state))
    }

    pub(crate) fn scope_correction_failed(&mut self, tool: &str, error: &str) -> bool {
        if tool != "pack:scopes" {
            return false;
        }
        let Some(state) = self
            .scope_correction_generation_mut()
            .and_then(|g| g.scope_correction.as_mut())
            .filter(|s| s.pending_draft_hash.is_some())
        else {
            return false;
        };
        state.pending_draft_hash = None;
        state.notice = Some(format!(
            "Correction not saved: {error}. Your draft is kept."
        ));
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.notice = None;
        }
        true
    }
}

fn matches_pending_correction(data: &Value, state: &ScopeCorrectionEditor) -> bool {
    serde_json::from_value::<kuzushi_core::workspace::ScanScopeCorrection>(
        data["record"]["correction"].clone(),
    )
    .is_ok_and(|correction| {
        correction.rejected == state.reference
            && Some(&correction.corrected_draft_sha256) == state.pending_draft_hash.as_ref()
    })
}

fn correction_result(data: &Value, state: &ScopeCorrectionEditor) -> Result<ScanScopeReview> {
    let review: ScanScopeReview = serde_json::from_value(data.clone())?;
    let correction = review
        .record
        .correction
        .as_ref()
        .context("Correction receipt is missing")?;
    anyhow::ensure!(
        correction.rejected == state.reference
            && Some(&correction.corrected_draft_sha256) == state.pending_draft_hash.as_ref(),
        "Correction result differs from your submitted draft"
    );
    anyhow::ensure!(
        review.record.acceptance.is_none() && review.record.generation.is_none(),
        "Correction result must remain unaccepted and marked as a manual change"
    );
    Ok(review)
}

impl StudyContextGeneration {
    pub(crate) fn has_corrected_scopes(&self) -> bool {
        self.generated_scopes
            .as_ref()
            .is_some_and(|review| review.record.correction.is_some())
    }
}
