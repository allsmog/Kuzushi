#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn word_boundary_right_skips_current_word_then_separator() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.input = "./path/to foo".to_string();
        app.cursor = 0;

        app.move_cursor_word_right();
        assert_eq!(app.cursor, 2);
        app.move_cursor_word_right();
        assert_eq!(app.cursor, 7);
        app.move_cursor_word_right();
        assert_eq!(app.cursor, 10);
    }

    #[test]
    fn show_completion_candidates_cover_show_subcommands() {
        let app = ShellApp::new(V2Config::default(), None);

        let aliases = app.completion_candidates("show a");
        assert!(aliases.contains(&"show aliases".to_string()));

        let all = app.completion_candidates("/show ");
        assert!(all.contains(&"/show modules".to_string()));
        assert!(all.contains(&"/show prompts".to_string()));
    }

    #[test]
    fn completion_candidates_cover_primary_and_nested_rule_tables() {
        let app = ShellApp::new(V2Config::default(), None);

        let config = app.completion_candidates("config runtime.");
        assert!(config.contains(&"config runtime.kind".to_string()));

        let context = app.completion_candidates("/context r");
        assert!(context.contains(&"/context regen".to_string()));

        let context_regen = app.completion_candidates("context regen a");
        assert!(context_regen.contains(&"context regen all".to_string()));

        let workspace = app.completion_candidates("workspace e");
        assert!(workspace.contains(&"workspace export".to_string()));

        let workspace_export = app.completion_candidates("workspace export f");
        assert!(workspace_export.contains(&"workspace export findings".to_string()));

        let auth = app.completion_candidates("auth login a");
        assert!(auth.contains(&"auth login anthropic".to_string()));

        let openai_auth = app.completion_candidates("auth login o");
        assert!(openai_auth.contains(&"auth login openai headless".to_string()));

        let task_mode = app.completion_candidates("task mode m");
        assert!(task_mode.contains(&"task mode manual".to_string()));
    }
}
