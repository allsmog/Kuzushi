use super::*;

impl ShellApp {
    pub fn plan_change_count(&self) -> usize {
        self.pending_plan
            .as_ref()
            .map(|plan| plan.changes.len())
            .unwrap_or(0)
    }

    pub fn plan_cursor_clamped(&self) -> usize {
        let total = self.plan_change_count();
        if total == 0 {
            0
        } else {
            self.plan_cursor.min(total - 1)
        }
    }

    pub fn plan_change_skipped(&self, idx: usize) -> bool {
        self.plan_skipped.contains(&idx)
    }

    pub fn move_plan_cursor(&mut self, delta: i32) {
        let total = self.plan_change_count();
        if total == 0 {
            self.plan_cursor = 0;
            return;
        }
        let cur = self.plan_cursor.min(total - 1) as i32;
        self.plan_cursor = (cur + delta).clamp(0, total as i32 - 1) as usize;
    }

    pub fn toggle_plan_change_skip(&mut self) {
        if self.plan_change_count() == 0 {
            return;
        }
        let idx = self.plan_cursor_clamped();
        if self.plan_skipped.contains(&idx) {
            self.plan_skipped.remove(&idx);
        } else {
            self.plan_skipped.insert(idx);
        }
    }
}
