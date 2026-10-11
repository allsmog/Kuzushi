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
        let text = generation.context_input["guidance"].as_str().unwrap_or("");
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
            generation.context_input["guidance"] =
                json!(generation.guidance_editor.as_ref().unwrap().text());
            generation.guidance_editing = false;
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
    if key.code == KeyCode::Enter {
        insert_guidance(generation, "\n");
        return;
    }
    if let KeyCode::Char(ch) = key.code {
        if matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
            insert_guidance(generation, &ch.to_string());
            return;
        }
    }
    generation.guidance_editor.as_mut().unwrap().handle_key(key);
}

fn insert_guidance(generation: &mut StudyContextGeneration, text: &str) {
    let editor = generation.guidance_editor.as_mut().unwrap();
    if text.contains('\0') || editor.text().len() + text.len() > 2048 {
        generation.guidance_notice =
            Some("Keep guidance within 2048 bytes; your draft is unchanged.".into());
        return;
    }
    editor.insert(text);
    generation.guidance_notice = None;
}
