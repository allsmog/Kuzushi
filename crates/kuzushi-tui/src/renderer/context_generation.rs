use super::*;
use crate::ui_view_models::context_generation::{generation_body, generation_lines};
use ratatui::widgets::{Block, Borders};

mod controls;
mod document;
mod scope_correction;

use controls::{
    generation_controls_area, generation_title_override, render_generation_state_controls,
};
use document::{
    render_generation_border, render_generation_document, render_regeneration_guidance,
};

pub(super) fn render_context_generation(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let Some(generation) = app.context_generation() else {
        return;
    };
    if let Some(editor) = generation
        .scope_correction
        .as_ref()
        .filter(|editor| editor.editing)
    {
        scope_correction::render(frame, area, editor);
        return;
    }
    if generation.guidance_editing {
        render_regeneration_guidance(frame, generation, area);
        return;
    }
    let viewport = frame.area();
    let body = generation_body(
        viewport.width,
        viewport.height,
        generation.has_text_editor() || generation.supports_brief_guidance(),
    );
    let (offset, max) = render_generation_document(frame, app, body, generation.scroll);
    render_generation_border(
        frame,
        area,
        generation.has_result() || generation.result_error.is_some(),
        generation.is_scope_proposal(),
        (offset, max),
        generation.show_rejected,
        generation_title_override(generation),
    );
    if let Some(config) = app.router.campaign().batch_scan_config.as_ref() {
        super::study_config::render_study_target(frame, config, area);
    }
    let controls = generation_controls_area(area, body, generation);
    render_generation_state_controls(frame, controls, generation, (offset, max));
}
