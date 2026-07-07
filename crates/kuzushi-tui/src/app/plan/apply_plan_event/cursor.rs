use super::*;

impl ShellApp {
    pub fn plan_change_count(&self) -> usize {
        self.engagement.plan_change_count()
    }

    pub fn plan_cursor_clamped(&self) -> usize {
        self.engagement.plan_cursor_clamped()
    }

    pub fn plan_change_skipped(&self, idx: usize) -> bool {
        self.engagement.plan_change_skipped(idx)
    }

    pub fn move_plan_cursor(&mut self, delta: i32) {
        self.engagement.move_plan_cursor(delta);
    }

    pub fn toggle_plan_change_skip(&mut self) {
        self.engagement.toggle_plan_change_skip();
    }
}
