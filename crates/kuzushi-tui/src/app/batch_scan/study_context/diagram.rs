//! Inspection stays bound to the selected immutable revision, never the active Map.
use super::*;
use crate::ui_view_models::study_context::diagram::{diagram_body, diagram_detail_lines};

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct StudyContextDiagram {
    pub(crate) selection: usize,
    pub(crate) details: bool,
    pub(crate) scroll: usize,
    pub(crate) notice: Option<String>,
}

impl ShellApp {
    pub(super) fn open_study_context_diagram(&mut self) {
        if self
            .study_context_picker()
            .and_then(|picker| picker.preview.as_ref())
            .is_none()
        {
            self.set_batch_config_notice(
                "Inspect a context revision with Enter before opening its diagram.",
            );
            return;
        }
        self.edit_context_picker(|config| {
            if let Some(picker) = config.context_picker.as_mut() {
                picker
                    .diagram
                    .get_or_insert_with(StudyContextDiagram::default);
                picker.diagram_visible = true;
            }
        });
    }

    pub(super) fn handle_study_diagram_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        if !self
            .study_context_picker()
            .is_some_and(|picker| picker.diagram_visible)
        {
            return None;
        }
        if code == KeyCode::Char('f') {
            return Some(self.open_context_diagram_findings());
        }
        match code {
            KeyCode::Esc | KeyCode::Char('q') => self.close_context_diagram(),
            KeyCode::Down | KeyCode::Char('j') => self.move_context_diagram(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_context_diagram(-1),
            KeyCode::Enter => self.edit_context_diagram(|state| state.details = !state.details),
            _ => self.page_context_diagram(code),
        }
        Some(InputUpdate::handled())
    }

    fn close_context_diagram(&mut self) {
        self.edit_context_picker(|config| {
            if let Some(picker) = config.context_picker.as_mut() {
                picker.diagram_visible = false;
            }
        });
    }

    fn open_context_diagram_findings(&mut self) -> InputUpdate {
        let Some((state, preview)) = self
            .study_context_picker()
            .and_then(|picker| picker.diagram.as_ref().zip(picker.preview.clone()))
        else {
            return InputUpdate::handled();
        };
        let selection = state.selection;
        self.open_dfd_finding_query(&preview.dfd, selection, None)
    }

    fn edit_context_diagram(&mut self, edit: impl FnOnce(&mut StudyContextDiagram)) {
        self.edit_context_picker(|config| {
            if let Some(diagram) = config
                .context_picker
                .as_mut()
                .and_then(|picker| picker.diagram.as_mut())
            {
                edit(diagram);
            }
        });
    }

    fn move_context_diagram(&mut self, direction: i64) {
        let count = self
            .study_context_picker()
            .and_then(|picker| picker.preview.as_ref())
            .map_or(0, |preview| {
                crate::ui_view_models::dfd_selectable_count(&preview.dfd)
            });
        self.edit_context_diagram(|state| {
            state.selection = (state.selection as i64 + direction)
                .clamp(0, count.saturating_sub(1) as i64) as usize;
            state.scroll = 0;
            state.notice = None;
        });
    }

    fn page_context_diagram(&mut self, code: KeyCode) {
        let viewport = self.viewport();
        let body = diagram_body(study_config_area(viewport.columns, viewport.rows));
        let max = diagram_detail_lines(self, body.width as usize)
            .len()
            .saturating_sub(body.height as usize);
        self.edit_context_diagram(|state| {
            if !state.details {
                return;
            }
            let scroll = state.scroll.min(max);
            state.scroll = match code {
                KeyCode::PageUp => scroll.saturating_sub(body.height as usize),
                KeyCode::PageDown => scroll.saturating_add(body.height as usize).min(max),
                KeyCode::Home => 0,
                KeyCode::End => max,
                _ => scroll,
            };
        });
    }
}
