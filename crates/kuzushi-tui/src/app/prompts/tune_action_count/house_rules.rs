use super::*;

impl ShellApp {
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

    pub(crate) fn tune_show(&mut self) {
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

    pub(crate) fn tune_set(&mut self, rest: &str) {
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

    pub(crate) fn write_house_rules(&mut self, path: &PathBuf, value: &str) {
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

    pub(crate) fn tune_reset(&mut self) {
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
}
