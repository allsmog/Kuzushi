use super::*;
use kuzushi_core::modules::{OptionSpec, OptionType};

impl ShellApp {
    pub(crate) fn option_setting_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        let values = match prefix_words {
            [_] => option_completion_values_for(self),
            [_, name] => CompletionValues::Owned(self.option_choice_completion_values(name)),
            _ => return Vec::new(),
        };
        complete_value_candidates(slash, prefix_words, current, values)
    }

    fn option_choice_completion_values(&self, name: &str) -> Vec<String> {
        let Some(spec) = self.setting_option_spec(name) else {
            return Vec::new();
        };
        if spec.option_type == OptionType::Bool {
            return vec!["yes".into(), "no".into()];
        }
        spec.choices.clone()
    }

    fn setting_option_spec(&self, name: &str) -> Option<&OptionSpec> {
        let tool_name = self.resolve_options_tool(None).ok()?;
        let tool = self.registry().resolve_tool(&tool_name)?;
        crate::app::options::find_option_spec(tool, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_completion_distinguishes_option_names_and_declared_values() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        assert!(app
            .completion_candidates("set semgrep")
            .contains(&"set semgrepConfig".into()));
        assert!(app.completion_candidates("set tasks semgrep").is_empty());
        assert!(app.completion_candidates("setg paths semgrep").is_empty());
        assert_eq!(
            app.completion_candidates("set task_mode man"),
            vec!["set task_mode manual"]
        );
        assert_eq!(
            app.completion_candidates("/setg triage y"),
            vec!["/setg triage yes"]
        );
    }

    #[test]
    fn tab_does_not_replace_an_unstructured_option_value_or_its_cursor() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_input("set tasks semgrep");
        let cursor = app.cursor();
        assert!(app.completion_preview().is_none());
        app.apply_completion();
        assert_eq!(app.input(), "set tasks semgrep");
        assert_eq!(app.cursor(), cursor);
    }
}
