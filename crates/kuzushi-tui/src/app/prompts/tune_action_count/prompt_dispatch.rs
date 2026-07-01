use super::*;

impl ShellApp {
    pub fn handle_prompt_verb(&mut self, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() {
            self.log(
                "prompt",
                "verbs: edit/show/diff/reset/set/list | mutate <name> \"value\" | approve <id> | reject <id>",
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
            "mutate" | "mutation" => self.prompt_mutate(rest),
            "approve" => self.prompt_approve_mutation(rest),
            "reject" => self.prompt_reject_mutation(rest),
            other => self.log(
                "prompt",
                format!("unknown prompt verb {other:?}; try edit/show/diff/reset/set/list/mutate/approve/reject"),
            ),
        }
    }
}
