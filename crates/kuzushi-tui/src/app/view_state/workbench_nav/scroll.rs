//! Clamped scroll offset for a dense depth-stack pane.

/// `scroll_to_bottom` parks at a sentinel that `resolved` clamps against the
/// real viewport at render time, so key handling never needs the pane height.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BoundedScroll {
    offset: u16,
}

impl BoundedScroll {
    pub fn scroll_by(&mut self, delta: isize) {
        self.offset = if delta < 0 {
            self.offset.saturating_sub(clamp_u16(delta.unsigned_abs()))
        } else {
            self.offset.saturating_add(clamp_u16(delta as usize))
        };
    }

    pub fn jump(&mut self, to_top: bool) {
        if to_top {
            self.scroll_to_top();
        } else {
            self.scroll_to_bottom();
        }
    }

    pub fn scroll_to_top(&mut self) {
        self.offset = 0;
    }

    pub fn scroll_to_bottom(&mut self) {
        self.offset = u16::MAX;
    }

    pub fn resolved(&self, total: usize, viewport: u16) -> u16 {
        self.offset.min(max_offset(total, viewport))
    }

    /// `(hidden_above, hidden_below)` — feeds the `↑N ↓N` border counter.
    pub fn overflow(&self, total: usize, viewport: u16) -> (usize, usize) {
        let above = self.resolved(total, viewport) as usize;
        let below = total.saturating_sub(above + viewport as usize);
        (above, below)
    }
}

fn max_offset(total: usize, viewport: u16) -> u16 {
    clamp_u16(total.saturating_sub(viewport as usize))
}

fn clamp_u16(value: usize) -> u16 {
    value.min(u16::MAX as usize) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_scroll_clamps_to_content() {
        let mut scroll = BoundedScroll::default();
        scroll.scroll_to_bottom();
        assert_eq!(scroll.resolved(10, 4), 6);
        assert_eq!(scroll.overflow(10, 4), (6, 0));
    }
}
