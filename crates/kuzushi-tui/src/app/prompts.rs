use std::path::PathBuf;

use super::{PromptsAction, ShellApp, TuneAction};

impl ShellApp {
    pub fn tune_action_count(&self) -> usize {
        TuneAction::ORDER.len()
    }

    pub fn tune_cursor_clamped(&self) -> usize {
        let total = self.tune_action_count();
        if total == 0 {
            0
        } else {
            self.tune_cursor.min(total - 1)
        }
    }

    pub fn current_tune_action(&self) -> Option<TuneAction> {
        TuneAction::ORDER.get(self.tune_cursor_clamped()).copied()
    }

    pub const PROMPT_VERB_NAMES: &'static [&'static str] = &["scan", "triage", "verify", "summary"];

    pub fn prompts_cursor_clamped(&self) -> usize {
        let total = Self::PROMPT_VERB_NAMES.len();
        if total == 0 {
            0
        } else {
            self.prompts_cursor.min(total - 1)
        }
    }

    pub fn current_prompt_verb_name(&self) -> Option<&'static str> {
        Self::PROMPT_VERB_NAMES
            .get(self.prompts_cursor_clamped())
            .copied()
    }

    pub fn move_prompts_cursor(&mut self, delta: i32) {
        let total = Self::PROMPT_VERB_NAMES.len();
        if total == 0 {
            self.prompts_cursor = 0;
            return;
        }
        let cur = self.prompts_cursor.min(total - 1) as i32;
        self.prompts_cursor = (cur + delta).clamp(0, total as i32 - 1) as usize;
    }

    pub fn activate_prompts_action(&mut self, action: PromptsAction) {
        let Some(name) = self.current_prompt_verb_name() else {
            return;
        };
        match action {
            PromptsAction::Show => self.handle_prompt_verb(&format!("show {name}")),
            PromptsAction::Edit => self.handle_prompt_verb(&format!("edit {name}")),
            PromptsAction::Diff => self.handle_prompt_verb(&format!("diff {name}")),
            PromptsAction::Reset => self.handle_prompt_verb(&format!("reset {name}")),
            PromptsAction::Set => {
                let prefill = format!("set {name} \"\"");
                self.cursor = prefill.chars().count() - 1;
                self.input = prefill;
                self.history_index = None;
            }
        }
    }

    pub fn move_tune_cursor(&mut self, delta: i32) {
        let total = self.tune_action_count();
        if total == 0 {
            self.tune_cursor = 0;
            return;
        }
        let cur = self.tune_cursor.min(total - 1) as i32;
        self.tune_cursor = (cur + delta).clamp(0, total as i32 - 1) as usize;
    }

    pub fn activate_tune_action(&mut self) {
        let Some(action) = self.current_tune_action() else {
            return;
        };
        match action {
            TuneAction::ShowHouseRules => self.handle_tune_verb("show"),
            TuneAction::ResetHouseRules => self.handle_tune_verb("reset"),
            TuneAction::EditHouseRules => {
                let prefill = "set \"\"".to_string();
                self.cursor = prefill.chars().count() - 1;
                self.input = prefill;
                self.history_index = None;
            }
        }
    }

    pub fn house_rules_path(&self) -> Option<PathBuf> {
        let module = self.focused_module.as_ref()?;
        let target = self.target.as_ref()?;
        Some(
            target
                .join(".kuzushi")
                .join("house-rules")
                .join(format!("{module}.md")),
        )
    }

    pub fn read_house_rules(&self) -> Option<String> {
        let path = self.house_rules_path()?;
        std::fs::read_to_string(path).ok()
    }

    pub fn handle_tune_verb(&mut self, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() {
            self.log("tune", "verbs: show | set \"<text>\" | reset");
            return;
        }
        let mut parts = raw.splitn(2, char::is_whitespace);
        let verb = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        match verb {
            "show" => self.tune_show(),
            "set" => self.tune_set(rest),
            "reset" => self.tune_reset(),
            other => self.log(
                "tune",
                format!("unknown tune verb {other:?}; try show/set/reset"),
            ),
        }
    }

    fn tune_show(&mut self) {
        match self.read_house_rules() {
            Some(text) if !text.trim().is_empty() => {
                self.log("tune", "house rules:".to_string());
                for line in text.lines().take(40) {
                    self.log("tune", line.to_string());
                }
            }
            _ => self.log("tune", "no house rules set"),
        }
    }

    fn tune_set(&mut self, rest: &str) {
        if rest.is_empty() {
            self.log(
                "tune",
                "set requires a quoted value: tune set \"focus on auth\"",
            );
            return;
        }
        let Some(path) = self.house_rules_path() else {
            self.log(
                "tune",
                "tune set requires a focused module and a workspace target",
            );
            return;
        };
        self.write_house_rules(&path, unquote_tune_value(rest));
    }

    fn write_house_rules(&mut self, path: &PathBuf, value: &str) {
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                self.log(
                    "error",
                    format!("could not create {}: {error}", parent.display()),
                );
                return;
            }
        }
        match std::fs::write(path, value) {
            Ok(_) => self.log(
                "tune",
                format!("wrote {} ({} bytes)", path.display(), value.len()),
            ),
            Err(error) => self.log(
                "error",
                format!("could not write {}: {error}", path.display()),
            ),
        }
    }

    fn tune_reset(&mut self) {
        let Some(path) = self.house_rules_path() else {
            self.log("tune", "tune reset requires a focused module and workspace");
            return;
        };
        if !path.exists() {
            self.log("tune", format!("no house rules at {}", path.display()));
            return;
        }
        match std::fs::remove_file(&path) {
            Ok(_) => self.log("tune", format!("removed {}", path.display())),
            Err(error) => self.log(
                "error",
                format!("could not remove {}: {error}", path.display()),
            ),
        }
    }

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

    fn prompt_path_for(&self, name: &str) -> Option<PathBuf> {
        let module = self.focused_module.as_ref()?;
        let target = self.target.clone()?;
        let safe = name.trim().replace(['/', '\\'], "");
        if safe.is_empty() {
            return None;
        }
        Some(
            target
                .join(".kuzushi")
                .join("prompts")
                .join(module)
                .join(format!("{safe}.md")),
        )
    }

    fn prompt_edit(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt edit requires a focused module and a workspace target. Next: /use <module>, then prompt edit <name>",
            );
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                self.log(
                    "error",
                    format!("could not create {}: {error}", parent.display()),
                );
                return;
            }
        }
        if !path.exists() {
            if let Err(error) = std::fs::write(&path, "") {
                self.log(
                    "error",
                    format!("could not seed {}: {error}", path.display()),
                );
                return;
            }
        }
        let editor = std::env::var("EDITOR").unwrap_or_else(|_| "${EDITOR}".to_string());
        self.log(
            "prompt",
            format!(
                "edit override at {}; suspend the shell and run `{editor} {0}` (Ctrl+C twice to exit when done)",
                path.display()
            ),
        );
    }

    fn prompt_show(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt show requires a focused module and workspace. Next: /use <module>",
            );
            return;
        };
        match std::fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => {
                self.log(
                    "prompt",
                    format!("override {} is empty (using default)", path.display()),
                );
            }
            Ok(text) => {
                self.log(
                    "prompt",
                    format!("override {} ({} bytes):", path.display(), text.len()),
                );
                for line in text.lines().take(40) {
                    self.log("prompt", line.to_string());
                }
            }
            Err(_) => {
                self.log(
                    "prompt",
                    format!("no override at {}; using built-in default", path.display()),
                );
            }
        }
    }

    fn prompt_diff(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt diff requires a focused module and workspace",
            );
            return;
        };
        if path.exists() {
            self.log(
                "prompt",
                format!("diff candidate: git diff -- {}", path.display()),
            );
        } else {
            self.log(
                "prompt",
                format!("no override file to diff at {}", path.display()),
            );
        }
    }

    fn prompt_reset(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt reset requires a focused module and workspace",
            );
            return;
        };
        if !path.exists() {
            self.log(
                "prompt",
                format!("no override at {} to reset", path.display()),
            );
            return;
        }
        match std::fs::remove_file(&path) {
            Ok(_) => self.log("prompt", format!("removed override {}", path.display())),
            Err(error) => self.log(
                "error",
                format!("could not remove {}: {error}", path.display()),
            ),
        }
    }

    fn prompt_set(&mut self, args: &str) {
        let mut parts = args.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if name.is_empty() || value.is_empty() {
            self.log(
                "prompt",
                "set requires a name and quoted value: prompt set triage \"focus on auth\"",
            );
            return;
        }
        // Strip outer quotes if present.
        let value = value
            .strip_prefix('"')
            .and_then(|stripped| stripped.strip_suffix('"'))
            .unwrap_or(value);
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt set requires a focused module and workspace",
            );
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                self.log(
                    "error",
                    format!("could not create {}: {error}", parent.display()),
                );
                return;
            }
        }
        match std::fs::write(&path, value) {
            Ok(_) => self.log(
                "prompt",
                format!("wrote {} ({} bytes)", path.display(), value.len()),
            ),
            Err(error) => self.log(
                "error",
                format!("could not write {}: {error}", path.display()),
            ),
        }
    }

    fn prompt_list(&mut self) {
        let Some(module) = self.focused_module.clone() else {
            self.log(
                "prompt",
                "list requires a focused module. Next: /use <module>",
            );
            return;
        };
        let Some(target) = self.target.clone() else {
            self.log("prompt", "list requires a workspace target");
            return;
        };
        let dir = target.join(".kuzushi").join("prompts").join(&module);
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                let mut names: Vec<String> = entries
                    .flatten()
                    .filter_map(|entry| {
                        entry
                            .file_name()
                            .into_string()
                            .ok()
                            .and_then(|name| name.strip_suffix(".md").map(str::to_string))
                    })
                    .collect();
                names.sort();
                if names.is_empty() {
                    self.log("prompt", format!("no overrides in {}", dir.display()));
                } else {
                    self.log("prompt", format!("overrides in {}:", dir.display()));
                    for name in names {
                        self.log("prompt", format!("  - {name}"));
                    }
                }
            }
            Err(_) => self.log(
                "prompt",
                format!("no override directory at {}", dir.display()),
            ),
        }
    }
}

fn unquote_tune_value(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn prompt_test_app(target: &std::path::Path) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(target.to_path_buf());
        app.focused_module = Some("sast".to_string());
        app
    }

    #[test]
    fn prompt_edit_seeds_override_file_and_logs_editor_command() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        app.handle_prompt_verb("edit triage");

        let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
        assert!(path.exists());
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("edit override at")));
    }

    #[test]
    fn prompt_list_reports_sorted_prompt_overrides_and_missing_state() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        app.handle_prompt_verb("list");
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("no override directory")));

        let dir = temp.path().join(".kuzushi/prompts/sast");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("triage.md"), "triage").unwrap();
        std::fs::write(dir.join("verify.md"), "verify").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();

        app.log.clear();
        app.handle_prompt_verb("list");

        let messages = app
            .log
            .iter()
            .map(|line| line.body.as_str())
            .collect::<Vec<_>>();
        assert!(messages.iter().any(|line| line.contains("overrides in")));
        assert!(messages.contains(&"  - triage"));
        assert!(messages.contains(&"  - verify"));
        assert!(!messages.contains(&"  - notes"));
    }
}
