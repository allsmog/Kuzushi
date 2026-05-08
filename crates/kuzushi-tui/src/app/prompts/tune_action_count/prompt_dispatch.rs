use super::*;

impl ShellApp {
    pub fn handle_prompt_verb(&mut self, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() {
            self.log(
                "prompt",
                "verbs: edit <name> | show <name> | diff <name> | reset <name> | set <name> \"value\"",
            );
            return;
        }
        let mut parts = raw.splitn(2, char::is_whitespace);
        let verb = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        match verb {
            "edit" => self.prompt_edit(rest),
            "show" => self.prompt_show(rest),
            "diff" => self.prompt_diff(rest),
            "reset" => self.prompt_reset(rest),
            "set" => self.prompt_set(rest),
            "list" => self.prompt_list(),
            other => self.log(
                "prompt",
                format!("unknown prompt verb {other:?}; try edit/show/diff/reset/set/list"),
            ),
        }
    }
}
