use super::*;

impl ShellApp {
    pub fn insert_str_at_cursor(&mut self, s: &str) {
        self.editor_mut().insert_str_at_cursor(s);
    }

    pub fn insert_char_at_cursor(&mut self, ch: char) {
        self.editor_mut().insert_char_at_cursor(ch);
    }

    pub fn backspace(&mut self) {
        self.editor_mut().backspace();
    }

    pub fn delete_forward(&mut self) {
        self.editor_mut().delete_forward();
    }

    pub fn move_cursor_left(&mut self) {
        self.editor_mut().move_cursor_left();
    }

    pub fn move_cursor_right(&mut self) {
        self.editor_mut().move_cursor_right();
    }

    pub fn move_cursor_home(&mut self) {
        self.editor_mut().move_cursor_home();
    }

    pub fn move_cursor_end(&mut self) {
        self.editor_mut().move_cursor_end();
    }

    pub fn delete_word_left(&mut self) {
        self.editor_mut().delete_word_left();
    }

    pub fn move_cursor_word_left(&mut self) {
        self.editor_mut().move_cursor_word_left();
    }

    pub fn move_cursor_word_right(&mut self) {
        self.editor_mut().move_cursor_word_right();
    }

    pub fn kill_to_start(&mut self) {
        self.editor_mut().kill_to_start();
    }

    pub fn kill_to_end(&mut self) {
        self.editor_mut().kill_to_end();
    }
}
