//! Depth-stack Workbench renderer (opt-in via `ui.workbench_depth_stack`).
//! Draws a breadcrumb over the active depth surface, with a self-contained
//! operations bar + key rail below it. Entry: [`render_workbench_depth`]; plain
//! projection: [`workbench_depth_lines`].

mod layout;
mod parts;
mod plain;
mod render;
mod widgets;

use crate::app::{WorkbenchDepth, WorkbenchNav};
use crate::ui_view_models::WorkbenchModel;
use layout::{frame_slots, FrameSlots};
use parts::{breadcrumb, echo};
use ratatui::layout::Rect;
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use widgets::{key_rail_line, operations_bar_line};

pub(crate) use plain::workbench_depth_lines;

pub(crate) fn render_workbench_depth(
    frame: &mut Frame<'_>,
    area: Rect,
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
) {
    let slots = frame_slots(area);
    render_chrome(frame, &slots, nav, model);
    if slots.body.width >= 8 && slots.body.height >= 3 {
        render_depth(frame, slots.body, nav, model);
    }
}

fn render_chrome(
    frame: &mut Frame<'_>,
    slots: &FrameSlots,
    nav: &WorkbenchNav,
    model: &WorkbenchModel,
) {
    if let Some(context) = slots.context {
        frame.render_widget(Paragraph::new(breadcrumb(nav, model)), context);
    }
    if let Some(ops) = slots.ops {
        let line = operations_bar_line(nav, &echo(nav, model), ops.width as usize);
        frame.render_widget(Paragraph::new(line), ops);
    }
    if let Some(keys) = slots.keys {
        frame.render_widget(Paragraph::new(key_rail_line(nav)), keys);
    }
}

fn render_depth(frame: &mut Frame<'_>, body: Rect, nav: &WorkbenchNav, model: &WorkbenchModel) {
    match nav.depth {
        WorkbenchDepth::List => render::render_list(frame, body, nav, model),
        WorkbenchDepth::Finding => render::render_finding(frame, body, nav, model),
        WorkbenchDepth::Record => render::render_record(frame, body, nav, model),
    }
}

#[cfg(test)]
mod tests;
