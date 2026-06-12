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
const MAX_STEPS: usize = 3;

pub(crate) struct TreeDiagram {
    pub model: AttackTree,
}

impl Widget for TreeDiagram {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let w = area.width;
        if w < 24 {
            text(
                buf,
                area,
                1,
                0,
                "widen terminal (≥24 cols) for the diagram",
                theme::T_MUTED,
            );
            return;
        }
        if let Some(hint) = &self.model.empty_hint {
            text(buf, area, 2, 1, hint, theme::T_MUTED);
            return;
        }
        let chains = &self.model.chains;
        let cols = chains.len().max(1) as u16;
        let col_w = w / cols;
        let center = |i: u16| col_w * i + col_w / 2;
        let box_w = col_w.saturating_sub(2).clamp(12, 30);
        let left = |i: u16| center(i).saturating_sub(box_w / 2);
        let root_cx = w / 2;
        render_goal_and_or_gate(buf, area, w, box_w, root_cx);

        for (i, chain) in chains.iter().enumerate() {
            self.render_chain(
                buf,
                area,
                i as u16,
                chain,
                root_cx,
                center(i as u16),
                left(i as u16),
                box_w,
            );
        }
    }
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
    fn render_chain(
        &self,
        buf: &mut Buffer,
        area: Rect,
        _i: u16,
        chain: &AttackChain,
        root_cx: u16,
        cx: u16,
        left: u16,
        box_w: u16,
    ) {
        connector_v(buf, area, (root_cx, 3), (cx, 7), theme::T_SUBTLE);
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
        connector_v(buf, area, (cx, prev_bottom + 1), (cx, y), theme::T_SUBTLE);
        boxed(
            buf,
            area,
            left,
            y,
            box_w,
            NODE_H,
            step,
            theme::T_MUTED,
            theme::T_MUTED,
        );
        prev_bottom = y + NODE_H - 1;
        y += NODE_H + STEP_GAP;
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
