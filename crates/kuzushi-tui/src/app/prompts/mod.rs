use super::*;
pub(crate) use super::*;

use self::{PromptsAction, ShellApp, TuneAction};
use std::path::PathBuf;
pub(crate) use tune_action_count::*;
pub(crate) use unquote_tune_value::*;
mod document;
#[cfg(test)]
mod tests;
mod tune_action_count;
mod unquote_tune_value;

impl ShellApp {
    fn invalidate_prompt_view_cache(&mut self) {
        self.workbench_cache()
            .borrow_mut()
            .invalidate_prompt_overrides();
        self.invalidate_view_hydration();
    }
}
