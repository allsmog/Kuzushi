//! Explicit local correction never retries a failed proposal or accepts scopes.
use super::*;

mod results;
use crate::app::{FieldEditor, ShellView};
use crossterm::event::{KeyEvent, KeyModifiers};
use kuzushi_core::workspace::{
    RejectedScopeRef, ScanScopeDraft, ScanScopeReview, MAX_REJECTED_SCOPE_BYTES,
};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScopeCorrectionEditor {
    pub reference: RejectedScopeRef,
    pub editor: FieldEditor,
    pub original: String,
    pub editing: bool,
    pub pending_draft_hash: Option<String>,
    pub notice: Option<String>,
}

impl ShellApp {
    pub(super) fn open_generation_preserving_correction(&mut self) {
        if let Some(state) = self
            .scope_correction_generation_mut()
            .and_then(|g| g.scope_correction.as_mut())
            .filter(|state| state.editor.text() != state.original)
        {
            state.notice = Some("Your JSON draft is kept. d output, then e resumes editing. Save it or Ctrl+R resets it before starting a new proposal.".into());
            return;
        }
        self.open_context_generation();
    }

    pub(super) fn open_scope_correction(&mut self) -> InputUpdate {
        if self
            .context_generation()
            .is_some_and(StudyContextGeneration::has_corrected_scopes)
        {
            return self.inspect_generated_scopes();
        }
        let result = self.load_scope_correction();
        match result {
            Ok(output) => self.install_scope_correction(output),
            Err(error) => {
                if let Some(generation) = self.scope_correction_generation_mut() {
                    generation.rejected_output = Some(Err(format!(
                        "Correction unavailable: {error:#}. Your draft is kept."
                    )));
                }
            }
        }
        InputUpdate::handled()
    }

    fn install_scope_correction(
        &mut self,
        output: kuzushi_core::capabilities::campaign::RejectedScopeDraft,
    ) {
        let Some(generation) = self.scope_correction_generation_mut() else {
            return;
        };
        let state = generation
            .scope_correction
            .get_or_insert_with(|| ScopeCorrectionEditor {
                reference: output.reference.clone(),
                editor: FieldEditor::new(output.candidate.clone()),
                original: output.candidate,
                editing: false,
                pending_draft_hash: None,
                notice: None,
            });
        if state.reference != output.reference {
            state.notice =
                Some("The retained output changed. Your correction draft is kept.".into());
            return;
        }
        state.editing = true;
    }

    fn load_scope_correction(
        &self,
    ) -> Result<kuzushi_core::capabilities::campaign::RejectedScopeDraft> {
        anyhow::ensure!(
            !self.has_running_work(),
            "Wait for active work before correcting scopes"
        );
        let config = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .context("Open scope diagnosis first")?;
        let receipt = self
            .context_generation()
            .and_then(|g| g.receipt.as_ref())
            .context("No frozen scope plan")?;
        let output = receipt
            .rejected_scope_draft(&config.target)?
            .context("No rejected scope text was retained")?;
        anyhow::ensure!(
            output.complete,
            "Partial output is read-only. Create a manual scope draft instead"
        );
        Ok(output)
    }

    pub(in crate::app::batch_scan) fn handle_scope_correction_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<InputUpdate> {
        let page = self.viewport().rows.saturating_sub(10).max(1) as usize;
        let width = crate::ui_view_models::study_config::study_config_area(
            self.viewport().columns,
            self.viewport().rows,
        )
        .width
        .saturating_sub(4)
        .max(1) as usize;
        self.scope_correction_generation_mut()?
            .scope_correction
            .as_ref()
            .filter(|s| s.editing)?;
        if key == KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL) {
            return Some(self.save_scope_correction());
        }
        let state = self
            .scope_correction_generation_mut()?
            .scope_correction
            .as_mut()?;
        if key.code == KeyCode::Esc {
            state.editing = false;
        } else if state.pending_draft_hash.is_none() {
            edit_correction(state, key, page, width);
        }
        Some(InputUpdate::handled())
    }

    pub(crate) fn capture_study_text_paste(&mut self, text: &str) -> bool {
        self.capture_scope_correction_paste(text) || self.capture_regeneration_guidance_paste(text)
    }

    fn capture_scope_correction_paste(&mut self, text: &str) -> bool {
        if self.shell_view() != ShellView::Campaign {
            return false;
        }
        let Some(state) = self
            .scope_correction_generation_mut()
            .and_then(|g| g.scope_correction.as_mut())
            .filter(|s| s.editing)
        else {
            return false;
        };
        if state.pending_draft_hash.is_none() {
            insert_correction(state, text);
        }
        true
    }

    fn save_scope_correction(&mut self) -> InputUpdate {
        if self.has_running_work() {
            return InputUpdate::handled();
        }
        let Some(state) = self
            .scope_correction_generation_mut()
            .and_then(|g| g.scope_correction.as_mut())
        else {
            return InputUpdate::handled();
        };
        match serde_json::from_str::<ScanScopeDraft>(state.editor.text()) {
            Ok(draft) => {
                state.pending_draft_hash = Some(kuzushi_core::options::prompt_content_sha256(
                    &serde_json::to_string(&draft).unwrap(),
                ));
                state.notice = Some(
                    "Checking source, membership and retained history. No model request.".into(),
                );
                let input =
                    json!({"operation":"recover","recoveryRef":state.reference,"draft":draft});
                self.dispatch_context_action("pack:scopes", input)
            }
            Err(error) => {
                state.notice = Some(format!(
                    "JSON needs correction: {error}. Your draft is kept."
                ));
                InputUpdate::handled()
            }
        }
    }

    fn scope_correction_generation_mut(&mut self) -> Option<&mut StudyContextGeneration> {
        self.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()?
            .context_generation
            .as_mut()
    }
}

fn edit_correction(state: &mut ScopeCorrectionEditor, key: KeyEvent, page: usize, width: usize) {
    if correction_navigation(state, key, page, width) {
        return;
    }
    let inserted = match (key.code, key.modifiers) {
        (KeyCode::Enter, KeyModifiers::NONE | KeyModifiers::SHIFT) => Some("\n".into()),
        (KeyCode::Tab, KeyModifiers::NONE) => Some("    ".into()),
        (KeyCode::Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => Some(c.to_string()),
        _ => None,
    };
    match inserted {
        Some(text) => insert_correction(state, &text),
        None => {
            state.editor.handle_key(key);
        }
    }
}

fn correction_navigation(
    state: &mut ScopeCorrectionEditor,
    key: KeyEvent,
    page: usize,
    width: usize,
) -> bool {
    if key == KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL) {
        state.editor = FieldEditor::new(state.original.clone());
        state.notice = None;
        return true;
    }
    let direction = match key.code {
        KeyCode::PageUp => -1,
        KeyCode::PageDown => 1,
        _ => return false,
    };
    state
        .editor
        .page_visual_rows(direction * page as isize, width);
    true
}

fn insert_correction(state: &mut ScopeCorrectionEditor, text: &str) {
    if text.contains('\0')
        || state.editor.text().len().saturating_add(text.len()) > MAX_REJECTED_SCOPE_BYTES
    {
        state.notice = Some(format!(
            "Keep JSON within {MAX_REJECTED_SCOPE_BYTES} bytes. Your draft is unchanged."
        ));
        return;
    }
    state.editor.insert(text);
    state.notice = None;
}
