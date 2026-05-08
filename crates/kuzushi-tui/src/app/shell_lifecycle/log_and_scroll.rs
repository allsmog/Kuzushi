use super::*;

impl ShellApp {
    pub fn log(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        self.log.push(LogLine::new(prefix, body));
        if self.log.len() > 500 {
            let overflow = self.log.len() - 500;
            self.log.drain(0..overflow);
        }
    }

    pub fn scroll_up(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_add(amount);
    }

    pub fn scroll_to_top(&mut self) {
        self.scroll_offset = 0;
    }

    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = u16::MAX;
    }

    pub(crate) fn sync_view_change(&mut self) -> bool {
        let current = Some(self.shell_view.clone());
        if self.prev_shell_view != current {
            self.scroll_offset = 0;
            self.prev_shell_view = current;
            true
        } else {
            false
        }
    }
}
