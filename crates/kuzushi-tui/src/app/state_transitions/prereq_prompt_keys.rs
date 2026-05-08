use super::*;

impl ShellApp {
    pub(super) fn handle_prereq_prompt_key(&mut self, key: KeyEvent) -> bool {
        if self.pending_prereq_prompt.is_none() || !key.modifiers.is_empty() {
            return false;
        }
        let Some(reuse) = prereq_prompt_reuse_decision(key.code) else {
            return false;
        };
        self.resolve_prereq_prompt(reuse);
        true
    }
}

fn prereq_prompt_reuse_decision(code: KeyCode) -> Option<bool> {
    let KeyCode::Char(ch) = code else {
        return None;
    };
    reuse_key(ch).or_else(|| regenerate_key(ch))
}

fn reuse_key(ch: char) -> Option<bool> {
    ['r', 'R', 'y', 'Y'].contains(&ch).then_some(true)
}

fn regenerate_key(ch: char) -> Option<bool> {
    ['g', 'G', 'n', 'N'].contains(&ch).then_some(false)
}
