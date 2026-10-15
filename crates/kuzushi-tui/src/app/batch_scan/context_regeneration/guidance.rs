use super::*;
use crate::app::{state_transitions::InputUpdate, FieldEditor};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl ShellApp {
    pub(in crate::app::batch_scan) fn edit_regeneration_guidance(&mut self) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(generation) = config.context_generation.as_mut() else {
            return;
        };
        if generation.receipt.is_some() {
            config.notice=Some("Guidance is frozen in this plan. n opens a separately approved draft to change it.".into());
            return;
        }
        let text = generation.context_input[generation.editor_field()]
            .as_str()
            .unwrap_or("");
        generation
            .guidance_editor
            .get_or_insert_with(|| FieldEditor::new(text));
        generation.guidance_editing = true;
    }

    pub(crate) fn handle_regeneration_guidance_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<InputUpdate> {
        let generation = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()?
            .context_generation
            .as_mut()?;
        if !generation.guidance_editing {
            return None;
        }
        if key.code == KeyCode::Esc {
            generation.guidance_editing = false;
            return Some(InputUpdate::handled());
        }
        if key == KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL) {
            save_guidance(generation);
            return Some(InputUpdate::handled());
        }
        edit_guidance(generation, key);
        Some(InputUpdate::handled())
    }

    pub(crate) fn capture_regeneration_guidance_paste(&mut self, text: &str) -> bool {
        let Some(generation) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_generation.as_mut())
            .filter(|generation| generation.guidance_editing)
        else {
            return false;
        };
        insert_guidance(generation, text);
        true
    }
}

fn edit_guidance(generation: &mut StudyContextGeneration, key: KeyEvent) {
    if let Some(text) = guidance_inserted_text(key) {
        insert_guidance(generation, &text);
        return;
    }
    if let Some(editor) = generation.guidance_editor.as_mut() {
        editor.handle_key(key);
    }
}

fn guidance_inserted_text(key: KeyEvent) -> Option<String> {
    match (key.code, key.modifiers) {
        (KeyCode::Enter, _) => Some("\n".into()),
        (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => Some(ch.to_string()),
        _ => None,
    }
}

fn insert_guidance(generation: &mut StudyContextGeneration, text: &str) {
    let limit = generation.editor_limit();
    let Some(editor) = generation.guidance_editor.as_mut() else {
        report_missing_editor(generation);
        return;
    };
    if text.contains('\0') || editor.text().len() + text.len() > limit {
        generation.guidance_notice = Some(format!(
            "Keep text within {limit} bytes; your draft is unchanged."
        ));
        return;
    }
    editor.insert(text);
    generation.guidance_notice = None;
}

fn save_guidance(generation: &mut StudyContextGeneration) {
    let field = generation.editor_field();
    let Some(editor) = generation.guidance_editor.as_ref() else {
        report_missing_editor(generation);
        return;
    };
    generation.context_input[field] = json!(editor.text());
    generation.guidance_editing = false;
}

fn report_missing_editor(generation: &mut StudyContextGeneration) {
    generation.guidance_notice =
        Some("Guidance editor unavailable. Press Esc to return; saved input is unchanged.".into());
}
