use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HouseRulesRead {
    Missing,
    Empty,
    Present(String),
    Unreadable(PathBuf),
}

impl ShellApp {
    pub fn house_rules_path(&self) -> Option<PathBuf> {
        let module = self.focused_module.as_ref()?;
        let target = self.target.as_ref()?;
        Some(kuzushi_core::house_rule_path(target, module))
    }

    pub fn read_house_rules(&self) -> Option<String> {
        match self.read_house_rules_state() {
            HouseRulesRead::Present(text) => Some(text),
            _ => None,
        }
    }

    pub(crate) fn read_house_rules_state(&self) -> HouseRulesRead {
        let Some(path) = self.house_rules_path() else {
            return HouseRulesRead::Missing;
        };
        if !path.exists() {
            return HouseRulesRead::Missing;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            return HouseRulesRead::Unreadable(path);
        };
        if text.trim().is_empty() {
            HouseRulesRead::Empty
        } else {
            HouseRulesRead::Present(text)
        }
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
        match self.read_house_rules_state() {
            HouseRulesRead::Present(text) => self.log_house_rules(&text),
            HouseRulesRead::Unreadable(path) => self.log(
                "tune",
                format!("could not read house rules at {}", path.display()),
            ),
            _ => self.log("tune", "no house rules set"),
        }
    }

    fn log_house_rules(&mut self, text: &str) {
        self.log("tune", "house rules:".to_string());
        for line in text.lines().take(40) {
            self.log("tune", line.to_string());
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
        if !self.prepare_house_rules_write_path(path) {
            return;
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

    fn prepare_house_rules_write_path(&mut self, path: &PathBuf) -> bool {
        if !self.ensure_house_rules_parent(path) {
            return false;
        }
        match house_rules_path_state(path) {
            HouseRulesPathState::File | HouseRulesPathState::Missing => true,
            HouseRulesPathState::Unreadable => {
                self.log(
                    "tune",
                    format!("could not set unreadable house rules at {}", path.display()),
                );
                false
            }
        }
    }

    fn ensure_house_rules_parent(&mut self, path: &PathBuf) -> bool {
        let Some(parent) = path.parent() else {
            return true;
        };
        match std::fs::create_dir_all(parent) {
            Ok(_) => true,
            Err(error) => {
                self.log(
                    "error",
                    format!("could not create {}: {error}", parent.display()),
                );
                false
            }
        }
    }

    pub(crate) fn tune_reset(&mut self) {
        let Some(path) = self.house_rules_path() else {
            self.log("tune", "tune reset requires a focused module and workspace");
            return;
        };
        match house_rules_path_state(&path) {
            HouseRulesPathState::File => self.remove_house_rules_file(&path),
            HouseRulesPathState::Missing => {
                self.log("tune", format!("no house rules at {}", path.display()));
            }
            HouseRulesPathState::Unreadable => self.log(
                "tune",
                format!(
                    "could not reset unreadable house rules at {}",
                    path.display()
                ),
            ),
        }
    }

    fn remove_house_rules_file(&mut self, path: &PathBuf) {
        match std::fs::remove_file(path) {
            Ok(_) => self.log("tune", format!("removed {}", path.display())),
            Err(error) => self.log(
                "error",
                format!("could not remove {}: {error}", path.display()),
            ),
        }
    }
}

enum HouseRulesPathState {
    File,
    Missing,
    Unreadable,
}

fn house_rules_path_state(path: &PathBuf) -> HouseRulesPathState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => HouseRulesPathState::File,
        Ok(_) => HouseRulesPathState::Unreadable,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => HouseRulesPathState::Missing,
        Err(_) => HouseRulesPathState::Unreadable,
    }
}
