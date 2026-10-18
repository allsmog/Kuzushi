//! Open historical accepted membership without planning or starting discovery.
use super::*;
use crate::app::{state_transitions::LinkedFindingsOrigin, ShellView};
use crate::commands::ShellCommand;
use anyhow::{Context, Result};

impl ShellApp {
    pub(super) fn open_selected_scope_findings(&mut self) -> InputUpdate {
        let (target, query) = match scope_findings_query(self.scope_review()) {
            Ok(selection) => selection,
            Err(error) => {
                self.scope_notice(format!("Saved findings unavailable: {error:#}"));
                return InputUpdate::handled();
            }
        };
        let origin = self.capture_linked_findings_origin(target, query.clone());
        self.router.campaign_mut().clear_active_batch();
        self.router.scope_review_mut().as_mut().unwrap().open = false;
        let update = self.reduce_hotkey_command(ShellCommand::FindingsFilter(query));
        self.router
            .scope_review_mut()
            .as_mut()
            .unwrap()
            .findings_origin = Some(origin);
        self.set_input_mode(crate::InputMode::Navigate);
        self.set_info_notice("Saved scope findings", "Back returns to these boundaries. Matches use this exact accepted record across saved runs; details retain current ledger truth.");
        update
    }

    pub(crate) fn scope_findings_return_is_available(&self) -> bool {
        self.shell_view() == ShellView::Workbench
            && self
                .scope_findings_origin()
                .is_some_and(|origin| self.linked_findings_origin_matches(origin))
    }

    pub(crate) fn restore_scope_findings_origin(&mut self) -> bool {
        if !self.scope_findings_return_is_available() {
            return false;
        }
        let state = self.router.scope_review_mut().as_mut().unwrap();
        let origin = state.findings_origin.take().unwrap();
        state.open = true;
        self.restore_linked_findings_origin(origin);
        true
    }

    fn scope_findings_origin(&self) -> Option<&LinkedFindingsOrigin> {
        self.scope_review()
            .filter(|state| !state.open)?
            .findings_origin
            .as_ref()
    }
}

fn scope_findings_query(state: Option<&ScopeReviewState>) -> Result<(std::path::PathBuf, String)> {
    let state = state.context("Open scope review first")?;
    anyhow::ensure!(
        state.files.is_none(),
        "Return from the file reader to choose a boundary"
    );
    let review = state
        .review
        .as_ref()
        .context("Build and accept boundaries first")?;
    anyhow::ensure!(
        review.record.acceptance.is_some(),
        "Accept boundaries before viewing their recorded discovery findings"
    );
    let scope = state.selected_id().context("Select an accepted boundary")?;
    Ok((
        state.target.clone(),
        format!(
            "scope:{scope} scope-record:{}",
            review.reference.record_hash
        ),
    ))
}
