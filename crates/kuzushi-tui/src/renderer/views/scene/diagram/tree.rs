//! Exploit chain as an attack tree: a rounded goal box at the root, an `OR`
//! gate fanning down to severity-ranked attack chains, each expanding (via an
//! `AND` gate when it has multiple steps) into stacked preconditions. Driven by
//! the real `AttackTree` model; laid out in equal columns so it never clips.

use super::*;
use crate::theme;
use crate::ui_view_models::{AttackChain, AttackTree};
use crate::ChainSeverity;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::widgets::Widget;

const NODE_H: u16 = 3;
const STEP_GAP: u16 = 1;
const MAX_STEPS: usize = 4;

pub(crate) struct TreeDiagram {
    pub model: AttackTree,
}

impl Widget for TreeDiagram {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let w = area.width;
        if render_width_hint(buf, area, w) {
            return;
        }
        if render_empty_tree(buf, area, &self.model) {
            return;
        }
        let layout = TreeLayout::new(w, self.model.chains.len());
        render_goal_and_or_gate(buf, area, w, layout.box_w, layout.root_cx);
        self.render_chains(buf, area, layout);
        render_hidden_chain_count(buf, area, self.model.hidden_chain_count);
    }
}

#[derive(Clone, Copy)]
struct TreeLayout {
    col_w: u16,
    box_w: u16,
    root_cx: u16,
}

impl TreeLayout {
    fn new(width: u16, chain_count: usize) -> Self {
        let col_w = width / chain_count.max(1) as u16;
        Self {
            col_w,
            box_w: col_w.saturating_sub(2).clamp(12, 30),
            root_cx: width / 2,
        }
    }

    fn center(self, index: u16) -> u16 {
        self.col_w * index + self.col_w / 2
    }

    fn left(self, index: u16) -> u16 {
        self.center(index).saturating_sub(self.box_w / 2)
    }
}

fn render_width_hint(buf: &mut Buffer, area: Rect, width: u16) -> bool {
    if width >= 24 {
        return false;
    }
    text(
        buf,
        area,
        1,
        0,
        "widen terminal (≥24 cols) for the diagram",
        diagram_muted(),
    );
    true
}

fn render_empty_tree(buf: &mut Buffer, area: Rect, model: &AttackTree) -> bool {
    let Some(hint) = &model.empty_hint else {
        return false;
    };
    render_empty_state_panel(
        buf,
        area,
        "no exploit chain",
        hint,
        &[("exploit-chain:scan", "build entry-to-impact chains")],
    );
    true
}

fn render_hidden_chain_count(buf: &mut Buffer, area: Rect, hidden: usize) {
    if hidden == 0 {
        return;
    }
    text(
        buf,
        area,
        2,
        area.height.saturating_sub(2),
        &format!("+{hidden} more chains"),
        diagram_muted(),
    );
}

/// Root goal box, centred, with the `OR` gate label beneath it.
fn render_goal_and_or_gate(buf: &mut Buffer, area: Rect, w: u16, box_w: u16, root_cx: u16) {
    let rw = box_w.max(24).min(w.saturating_sub(2));
    boxed(
        buf,
        area,
        (w - rw) / 2,
        0,
        rw,
        3,
        "☠ attacker goal — impact",
        theme::SEV_CRITICAL,
        theme::T_HEADING,
    );
    text(
        buf,
        area,
        root_cx + 2,
        4,
        "◇ OR — any one chain",
        theme::T_ACCENT,
    );
}

impl TreeDiagram {
    fn render_chains(&self, buf: &mut Buffer, area: Rect, layout: TreeLayout) {
        for (index, chain) in self.model.chains.iter().enumerate() {
            let index = index as u16;
            self.render_chain(
                buf,
                area,
                chain,
                layout.root_cx,
                layout.center(index),
                layout.left(index),
                layout.box_w,
            );
        }
    }

    fn render_chain(
        &self,
        buf: &mut Buffer,
        area: Rect,
        chain: &AttackChain,
        root_cx: u16,
        cx: u16,
        left: u16,
        box_w: u16,
    ) {
        connector_v(buf, area, (root_cx, 3), (cx, 7), diagram_subtle());
        let color = chain_color(chain.severity);
        boxed(
            buf,
            area,
            left,
            7,
            box_w,
            NODE_H,
            &chain_label(chain),
            color,
            color,
        );

        if chain.steps.len() > 1 {
            text(buf, area, left, 10, "◆ AND", theme::T_WARN);
        }
        render_steps(buf, area, chain, cx, left, box_w);
    }
}

/// Stack the chain's precondition steps beneath its box, connected vertically.
fn render_steps(buf: &mut Buffer, area: Rect, chain: &AttackChain, cx: u16, left: u16, box_w: u16) {
    let mut prev_bottom = 7 + NODE_H - 1; // chain box bottom (= 9)
    let mut y = 12;
    for step in chain.steps.iter().take(MAX_STEPS) {
        connector_v(buf, area, (cx, prev_bottom + 1), (cx, y), diagram_subtle());
        boxed(
            buf,
            area,
            left,
            y,
            box_w,
            NODE_H,
            step,
            diagram_muted(),
            diagram_muted(),
        );
        prev_bottom = y + NODE_H - 1;
        y += NODE_H + STEP_GAP;
    }
    if chain.hidden_step_count > 0 {
        text(
            buf,
            area,
            left.saturating_add(1),
            y,
            &format!("+{} more steps", chain.hidden_step_count),
            diagram_muted(),
        );
    }
}

fn chain_label(chain: &AttackChain) -> String {
    format!("{} · {}", chain.title, chain.severity.label())
}

fn chain_color(severity: ChainSeverity) -> Color {
    match severity {
        ChainSeverity::Critical => theme::SEV_CRITICAL,
        ChainSeverity::High => theme::SEV_HIGH,
        ChainSeverity::Medium => theme::SEV_MEDIUM,
    }
}
