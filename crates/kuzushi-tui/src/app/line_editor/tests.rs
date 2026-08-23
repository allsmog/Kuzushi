#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn word_boundary_right_skips_current_word_then_separator() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_input("./path/to foo");
        app.set_cursor(0);

        app.move_cursor_word_right();
        assert_eq!(app.cursor(), 2);
        app.move_cursor_word_right();
        assert_eq!(app.cursor(), 7);
        app.move_cursor_word_right();
        assert_eq!(app.cursor(), 10);
    }

    #[test]
    fn bare_digit_does_not_complete_to_model_switch_command() {
        // Regression: `aliases: &["model 1", ...]` on the `model [choice]`
        // spec used to feed the literal example value "model 1" into
        // completion candidates. A bare "1" is a subsequence of "model 1",
        // so any operator typing digit page-navigation shortcuts while
        // still in Prompt mode (rather than Navigate mode) would see the
        // composer Tab-complete into a model-switch command with no
        // relation to what they typed. See #172 finding 6.
        let app = ShellApp::new(V2Config::default(), None);

        let candidates = app.completion_candidates("1");
        assert!(
            !candidates.iter().any(|c| c.starts_with("model")),
            "bare digit must not fuzzy-match a model-switch example alias: {candidates:?}"
        );
    }

    #[test]
    fn bare_digit_does_not_complete_to_a_finding_suppression() {
        // Regression: the earlier fix only excluded examples that extend
        // their own base command's head, so `"/x F-0001 --reason
        // false-positive"` — the usage example written against `suppress`'s
        // short synonym `/x` — still reached the completion pool. A bare `1`
        // is a subsequence of it, so a digit typed in Prompt mode (rather
        // than Navigate mode) put the operator one Tab+Enter away from
        // drafting a suppression of a finding id nobody named. See #172
        // finding 6, 2026-08-22 run.
        let app = ShellApp::new(V2Config::default(), None);

        let candidates = app.completion_candidates("1");
        assert!(
            candidates.is_empty(),
            "a bare digit names no command: {candidates:?}"
        );
    }

    #[test]
    fn argument_bearing_alias_completes_to_its_routed_head() {
        // The example's own command form is real and stays reachable: `x`
        // routes to suppress and `v` to verify (argument_commands/nested.rs).
        let app = ShellApp::new(V2Config::default(), None);

        assert!(app.completion_candidates("/x").contains(&"/x".to_string()));
        assert!(app.completion_candidates("/v").contains(&"/v".to_string()));
    }

    #[test]
    fn routed_synonym_aliases_still_complete() {
        // Regression: the fix for the above must not, in turn, drop real
        // routed synonyms that happen to share their base command's word
        // count (e.g. "patch discard" routes to PatchCommand::Reject
        // alongside "patch reject" — see argument_commands/nested.rs). Only
        // aliases that *extend* their base command's head with extra
        // literal words (the "model 1" shape) are value-filled examples.
        let app = ShellApp::new(V2Config::default(), None);

        assert!(
            app.completion_candidates("discard")
                .contains(&"patch discard".to_string()),
            "patch discard is a real routed synonym, not an example"
        );
        assert!(
            app.completion_candidates("run")
                .contains(&"strategy run".to_string()),
            "strategy run is a real routed synonym, not an example"
        );
        assert!(
            app.completion_candidates("history")
                .contains(&"threats history".to_string()),
            "threats history is a real routed synonym, not an example"
        );
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

    #[test]
    fn slash_command_completion_ignores_argument_aliases() {
        let app = ShellApp::new(V2Config::default(), None);
        let candidates = app.completion_candidates("/con");

        assert_eq!(candidates.first().map(String::as_str), Some("/context"));
        assert!(!candidates.contains(&"/phase confirm".to_string()));
    }

    #[test]
    fn completion_exposes_phase_and_full_pipeline_verbs() {
        let app = ShellApp::new(V2Config::default(), None);

        for command in ["/map", "/scan", "/review", "/prove", "/fix", "/full"] {
            assert!(
                app.completion_candidates(command)
                    .contains(&command.to_string()),
                "missing completion for {command}"
            );
        }
        assert!(app
            .completion_candidates("/pipe")
            .contains(&"/pipeline".to_string()));
    }

    #[test]
    fn threats_and_prompt_subverbs_complete() {
        let app = ShellApp::new(V2Config::default(), None);

        let threats = app.completion_candidates("threats s");
        assert!(threats.contains(&"threats summary".to_string()));
        assert!(threats.contains(&"threats stride".to_string()));

        let prompt = app.completion_candidates("prompt d");
        assert!(prompt.contains(&"prompt diff".to_string()));
    }

    #[test]
    fn fuzzy_completion_finds_non_prefix_match() {
        let app = ShellApp::new(V2Config::default(), None);
        // "sgrep" is a subsequence of "semgrep:*" tool ids but not a prefix.
        let candidates = app.completion_candidates("run sgrep");
        assert!(
            candidates.iter().any(|c| c.contains("semgrep")),
            "fuzzy matching should surface semgrep from `sgrep`: {candidates:?}"
        );
    }

    #[test]
    fn completion_preview_names_fuzzy_candidate_when_suffix_is_not_enough() {
        let mut app = ShellApp::new(V2Config::default(), None);
        // "fnd" alone now also fuzzy-matches the shorter `find` verb, so use a
        // suffix ("gs") that only the `findings*` family contains to keep this
        // test unambiguous.
        app.set_input("fndgs");

        let preview = app.completion_preview().expect("fuzzy preview");

        assert!(preview.contains("findings"), "{preview}");
    }

    #[test]
    fn attach_completion_lists_workspace_files() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("docs")).unwrap();
        std::fs::write(temp.path().join("docs").join("design.md"), "design").unwrap();
        std::fs::create_dir(temp.path().join(".kuzushi")).unwrap();
        std::fs::write(temp.path().join(".kuzushi").join("state.json"), "{}").unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_active_view_blocking();

        let candidates = app.completion_candidates("attach des");

        assert!(candidates.contains(&"attach docs/design.md".to_string()));
        assert!(!candidates
            .iter()
            .any(|candidate| candidate.contains(".kuzushi")));
    }

    #[test]
    fn subverb_listing_matches_completion_for_every_group_verb() {
        for verb in [
            "task",
            "context",
            "workspace",
            "auth",
            "show",
            "threats",
            "prompt",
        ] {
            assert!(
                subverb_listing(verb).is_some(),
                "{verb} should expose a sub-verb listing"
            );
        }
        assert!(subverb_listing("scan").is_none());
    }
}
