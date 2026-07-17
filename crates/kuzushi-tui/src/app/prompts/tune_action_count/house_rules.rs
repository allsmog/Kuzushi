use super::*;
use std::path::Path;

const MAX_HOUSE_RULE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HouseRulesRead {
    Missing,
    Empty,
    Present(String),
    Unreadable(PathBuf),
}

impl ShellApp {
    pub fn house_rules_path(&self) -> Option<PathBuf> {
        let module = self.focused_module()?;
        let target = self.target_path_buf()?;
        Some(kuzushi_core::house_rule_path(target, module))
    }

    pub fn read_house_rules(&self) -> Option<String> {
        match self.read_house_rules_state() {
            HouseRulesRead::Present(text) => Some(text),
            _ => None,
        }
    }

    pub(crate) fn read_house_rules_state(&self) -> HouseRulesRead {
        let (Some(target), Some(path)) = (self.target_path_buf(), self.house_rules_path()) else {
            return HouseRulesRead::Missing;
        };
        house_rules_state_for_path(Some(target.as_path()), Some(path))
    }

    pub(crate) fn handle_tune_verb(&mut self, raw: &str) -> Vec<ShellEffect> {
        self.reduce_tune_verb(raw)
    }

    pub(crate) fn reduce_tune_verb(&mut self, raw: &str) -> Vec<ShellEffect> {
        let raw = raw.trim();
        if raw.is_empty() {
            self.log("tune", "verbs: show | set \"<text>\" | reset");
            return Vec::new();
        }
        let mut parts = raw.splitn(2, char::is_whitespace);
        let verb = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        match verb {
            "show" => self.reduce_tune_show(),
            "set" => self.reduce_tune_set(rest),
            "reset" => self.reduce_tune_reset(),
            other => {
                self.log(
                    "tune",
                    format!("unknown tune verb {other:?}; try show/set/reset"),
                );
                Vec::new()
            }
        }
    }

    pub(crate) fn reduce_tune_show(&mut self) -> Vec<ShellEffect> {
        vec![ShellEffect::ShowHouseRules(HouseRulesShow {
            path: self.house_rules_path(),
        })]
    }

    pub(crate) fn show_house_rules_effect(&mut self, show: HouseRulesShow) {
        let target = self.target_owned();
        let state = house_rules_state_for_path(target.as_deref(), show.path);
        self.set_tune_house_rules(state.clone());
        match state {
            HouseRulesRead::Present(text) => self.log_house_rules(&text),
            HouseRulesRead::Unreadable(path) => self.log(
                "tune",
                format!("could not read house rules at {}", path.display()),
            ),
            _ => self.log("tune", "no house rules set"),
        }
    }

    pub(crate) fn refresh_house_rules_effect(&mut self, refresh: HouseRulesRefresh) {
        let target = self.target_owned();
        let state = house_rules_state_for_path(target.as_deref(), refresh.path);
        self.set_tune_house_rules(state);
    }

    fn log_house_rules(&mut self, text: &str) {
        self.log("tune", "house rules:".to_string());
        for line in text.lines().take(40) {
            self.log("tune", line.to_string());
        }
    }

    pub(crate) fn reduce_tune_set(&mut self, rest: &str) -> Vec<ShellEffect> {
        if rest.is_empty() {
            self.log(
                "tune",
                "set requires a quoted value: tune set \"focus on auth\"",
            );
            return Vec::new();
        }
        let Some(path) = self.house_rules_path() else {
            self.log(
                "tune",
                "tune set requires a focused module and a workspace target",
            );
            return Vec::new();
        };
        vec![ShellEffect::WriteHouseRules(HouseRulesWrite {
            path,
            value: unquote_tune_value(rest).to_string(),
        })]
    }

    pub(crate) fn write_house_rules_effect(&mut self, write: HouseRulesWrite) {
        let Some(target) = self.target_owned() else {
            self.log("error", "could not write house rules without a target");
            return;
        };
        let Some(relative) = self.authorize_house_rules_write(&target, &write.path) else {
            return;
        };
        match kuzushi_core::workspace::write_workspace_state_file(
            &target,
            &relative,
            write.value.as_bytes(),
        ) {
            Ok(_) => self.finish_house_rules_write(&write),
            Err(error) => self.log(
                "error",
                format!("could not write {}: {error}", write.path.display()),
            ),
        }
    }

    fn authorize_house_rules_write(&mut self, target: &Path, path: &Path) -> Option<PathBuf> {
        if matches!(
            house_rules_path_state(target, path),
            HouseRulesPathState::Unreadable
        ) {
            self.log(
                "tune",
                format!("could not set unreadable house rules at {}", path.display()),
            );
            return None;
        }
        match path.strip_prefix(target) {
            Ok(relative) => Some(relative.to_path_buf()),
            Err(_) => {
                self.log(
                    "error",
                    format!("house rules path is outside target: {}", path.display()),
                );
                None
            }
        }
    }

    fn finish_house_rules_write(&mut self, write: &HouseRulesWrite) {
        self.set_tune_house_rules(house_rules_state_from_text(write.value.clone()));
        self.log(
            "tune",
            format!(
                "wrote {} ({} bytes)",
                write.path.display(),
                write.value.len()
            ),
        );
    }

    pub(crate) fn reduce_tune_reset(&mut self) -> Vec<ShellEffect> {
        let Some(path) = self.house_rules_path() else {
            self.log("tune", "tune reset requires a focused module and workspace");
            return Vec::new();
        };
        vec![ShellEffect::ResetHouseRules(HouseRulesReset { path })]
    }

    pub(crate) fn reset_house_rules_effect(&mut self, reset: HouseRulesReset) {
        let Some(target) = self.target_owned() else {
            self.log("error", "could not reset house rules without a target");
            return;
        };
        match house_rules_path_state(&target, &reset.path) {
            HouseRulesPathState::File => self.remove_house_rules_file(&target, &reset.path),
            HouseRulesPathState::Missing => {
                self.set_tune_house_rules(HouseRulesRead::Missing);
                self.log(
                    "tune",
                    format!("no house rules at {}", reset.path.display()),
                );
            }
            HouseRulesPathState::Unreadable => {
                self.log(
                    "tune",
                    format!(
                        "could not reset unreadable house rules at {}",
                        reset.path.display()
                    ),
                );
                self.set_tune_house_rules(HouseRulesRead::Unreadable(reset.path));
            }
        }
    }

    fn remove_house_rules_file(&mut self, target: &Path, path: &PathBuf) {
        if !matches!(
            house_rules_path_state(target, path),
            HouseRulesPathState::File
        ) {
            self.log(
                "error",
                format!("house rules path changed before reset: {}", path.display()),
            );
            return;
        }
        let relative = match path.strip_prefix(target) {
            Ok(relative) => relative,
            Err(_) => {
                self.log("error", "house rules path escaped the active target");
                return;
            }
        };
        match kuzushi_core::workspace::remove_workspace_state_file(target, relative) {
            Ok(true) => {
                self.set_tune_house_rules(HouseRulesRead::Missing);
                self.log("tune", format!("removed {}", path.display()));
            }
            Ok(false) => self.log("tune", format!("no house rules at {}", path.display())),
            Err(error) => self.log(
                "error",
                format!("could not remove {}: {error}", path.display()),
            ),
        }
    }

    fn set_tune_house_rules(&mut self, house_rules: HouseRulesRead) {
        self.router.tune_mut().set_house_rules(house_rules);
    }
}

fn house_rules_state_for_path(target: Option<&Path>, path: Option<PathBuf>) -> HouseRulesRead {
    let (Some(target), Some(path)) = (target, path) else {
        return HouseRulesRead::Missing;
    };
    let text = match kuzushi_core::workspace::read_optional_workspace_text(
        target,
        &path,
        MAX_HOUSE_RULE_BYTES,
    ) {
        Ok(Some(text)) => text,
        Ok(None) => return HouseRulesRead::Missing,
        Err(_) => return HouseRulesRead::Unreadable(path),
    };
    if text.trim().is_empty() {
        HouseRulesRead::Empty
    } else {
        HouseRulesRead::Present(text)
    }
}

fn house_rules_state_from_text(text: String) -> HouseRulesRead {
    if text.trim().is_empty() {
        HouseRulesRead::Empty
    } else {
        HouseRulesRead::Present(text)
    }
}

enum HouseRulesPathState {
    File,
    Missing,
    Unreadable,
}

fn house_rules_path_state(target: &Path, path: &Path) -> HouseRulesPathState {
    match kuzushi_core::workspace::read_optional_workspace_text(target, path, MAX_HOUSE_RULE_BYTES)
    {
        Ok(Some(_)) => HouseRulesPathState::File,
        Ok(None) => HouseRulesPathState::Missing,
        Err(_) => HouseRulesPathState::Unreadable,
    }
}
