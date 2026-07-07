use super::*;

impl ShellApp {
    pub(crate) fn reduce_pwn_command(&mut self, command: &PwnCommand) -> Vec<ShellEffect> {
        self.set_shell_view(ShellView::Pwn);
        if let Some(effects) = self.reduce_pwn_local_command(command) {
            return effects;
        }
        if let Some(effects) = self.reduce_pwn_binary_command(command) {
            return effects;
        }
        self.reduce_pwn_target_or_candidates_command(command)
    }

    fn reduce_pwn_local_command(&mut self, command: &PwnCommand) -> Option<Vec<ShellEffect>> {
        match command {
            PwnCommand::Show => {
                self.log("pwn", "dashboard");
                Some(vec![ShellEffect::RefreshPwnState])
            }
            PwnCommand::Target(path) => {
                let pwn = self.pwn_view_mut();
                pwn.target = Some(path.clone());
                pwn.binary = Some(path.clone());
                self.log("pwn", format!("target {}", path.display()));
                Some(vec![ShellEffect::RefreshPwnState])
            }
            _ => None,
        }
    }

    fn reduce_pwn_binary_command(&mut self, command: &PwnCommand) -> Option<Vec<ShellEffect>> {
        match command {
            PwnCommand::Profile => Some(self.reduce_pwn_binary_tool("pwn:profile-binary")),
            PwnCommand::Reverse(function) => Some(self.reduce_pwn_reverse_tool(function)),
            PwnCommand::State => Some(self.reduce_pwn_binary_tool("pwn:state")),
            _ => None,
        }
    }

    fn reduce_pwn_target_or_candidates_command(
        &mut self,
        command: &PwnCommand,
    ) -> Vec<ShellEffect> {
        match command {
            PwnCommand::Auto => self.reduce_pwn_auto_tool(),
            PwnCommand::Candidates(target) => self.reduce_pwn_candidates_tool(target),
            PwnCommand::Unsupported(verb) => {
                self.log(
                    "error",
                    format!("unknown pwn command {verb:?}. Next: pwn, pwn target <path>, pwn auto"),
                );
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn reduce_pwn_binary_tool(&mut self, tool_name: &str) -> Vec<ShellEffect> {
        let Some(binary) = self.pwn_binary_for_command() else {
            return Vec::new();
        };
        self.reduce_pwn_tool(tool_name, serde_json::json!({ "binary": binary }))
    }

    fn reduce_pwn_reverse_tool(&mut self, function: &Option<String>) -> Vec<ShellEffect> {
        let Some(binary) = self.pwn_binary_for_command() else {
            return Vec::new();
        };
        let mut input = serde_json::json!({ "binary": binary });
        if let Some(function) = function {
            input["function"] = serde_json::json!(function);
        }
        self.reduce_pwn_tool("pwn:reverse", input)
    }

    fn reduce_pwn_auto_tool(&mut self) -> Vec<ShellEffect> {
        let Some(target) = self.pwn_target_for_command() else {
            return Vec::new();
        };
        self.reduce_pwn_tool("pwn:auto-solve", serde_json::json!({ "target": target }))
    }

    fn reduce_pwn_candidates_tool(&mut self, target: &str) -> Vec<ShellEffect> {
        let Some(state_id) = self.pwn_state_id_for_candidates() else {
            self.log(
                "error",
                "pwn candidates needs a profiled binary/state first. Next: pwn profile",
            );
            return Vec::new();
        };
        self.reduce_pwn_tool(
            "pwn:run-candidates",
            serde_json::json!({ "target": target, "stateId": state_id }),
        )
    }

    pub(crate) fn cache_pwn_snapshot(
        &mut self,
        tool_name: &str,
        result: &serde_json::Value,
    ) -> Vec<ShellEffect> {
        match tool_name {
            "pwn:profile-binary" => self.cache_pwn_profile_snapshot(result),
            "pwn:reverse" => {
                self.cache_pwn_reverse_snapshot(result);
                Vec::new()
            }
            "pwn:auto-solve" => self.cache_pwn_auto_solve_snapshot(result),
            "pwn:state" => {
                self.cache_pwn_state_snapshot(result);
                Vec::new()
            }
            "pwn:run-candidates" => self.cache_pwn_candidates_snapshot(result),
            _ => Vec::new(),
        }
    }

    fn cache_pwn_profile_snapshot(&mut self, result: &serde_json::Value) -> Vec<ShellEffect> {
        let existing_binary = self.pwn_view().binary.clone();
        let existing_state_path = self.pwn_view().state_path.clone();
        let pwn = self.pwn_view_mut();
        pwn.profile_snapshot = Some(result.clone());
        pwn.binary = path_value(result, "binary").or(existing_binary);
        pwn.state_path = path_value(result, "statePath").or(existing_state_path);
        vec![ShellEffect::RefreshPwnState]
    }

    fn cache_pwn_reverse_snapshot(&mut self, result: &serde_json::Value) {
        let pwn = self.pwn_view_mut();
        pwn.reverse_snapshots.push(result.clone());
        if pwn.reverse_snapshots.len() > 12 {
            let overflow = pwn.reverse_snapshots.len() - 12;
            pwn.reverse_snapshots.drain(0..overflow);
        }
    }

    fn cache_pwn_auto_solve_snapshot(&mut self, result: &serde_json::Value) -> Vec<ShellEffect> {
        let existing_state_path = self.pwn_view().state_path.clone();
        let pwn = self.pwn_view_mut();
        pwn.auto_solve_snapshot = Some(result.clone());
        pwn.state_path = path_value(result, "statePath").or(existing_state_path);
        vec![ShellEffect::RefreshPwnState]
    }

    fn cache_pwn_state_snapshot(&mut self, result: &serde_json::Value) {
        let existing_state_path = self.pwn_view().state_path.clone();
        let pwn = self.pwn_view_mut();
        pwn.state_snapshot = Some(result.clone());
        pwn.state_path = path_value(result, "statePath").or(existing_state_path);
    }

    fn cache_pwn_candidates_snapshot(&mut self, result: &serde_json::Value) -> Vec<ShellEffect> {
        self.pwn_view_mut().candidates_snapshot = Some(result.clone());
        vec![ShellEffect::RefreshPwnState]
    }

    fn reduce_pwn_tool(&mut self, tool_name: &str, input: serde_json::Value) -> Vec<ShellEffect> {
        let input = match serde_json::to_string(&input) {
            Ok(input) => input,
            Err(error) => {
                self.log("error", format!("could not encode pwn tool input: {error}"));
                return Vec::new();
            }
        };
        self.reduce_run_tool(Some(tool_name.to_string()), Some(input))
    }

    fn pwn_target_for_command(&mut self) -> Option<String> {
        self.pwn_view()
            .target
            .as_ref()
            .or(self.pwn_view().binary.as_ref())
            .map(|path| path.display().to_string())
            .or_else(|| {
                self.log("error", "pwn target is not set. Next: pwn target <path>");
                None
            })
    }

    fn pwn_binary_for_command(&mut self) -> Option<String> {
        self.pwn_view()
            .binary
            .as_ref()
            .or(self.pwn_view().target.as_ref())
            .map(|path| path.display().to_string())
            .or_else(|| {
                self.log("error", "pwn binary is not set. Next: pwn target <path>");
                None
            })
    }

    fn pwn_state_id_for_candidates(&mut self) -> Option<String> {
        self.pwn_view()
            .state_snapshot
            .as_ref()
            .and_then(|state| state.get("stateId"))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                self.pwn_view()
                    .profile_snapshot
                    .as_ref()
                    .and_then(|profile| profile.get("stateId"))
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            })
            .or_else(|| {
                self.pwn_view()
                    .state_snapshot
                    .as_ref()
                    .and_then(|state| state.get("state"))
                    .and_then(|state| state.get("stateId"))
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            })
    }

    pub(crate) fn refresh_pwn_state_from_disk(&mut self) {
        if self.pwn_view().state_path.is_none() {
            let state_path = latest_pwn_state_path(self.target_path_buf());
            self.pwn_view_mut().state_path = state_path;
        }
        let Some(path) = self.pwn_view().state_path.clone() else {
            return;
        };
        let Ok(body) = std::fs::read_to_string(&path) else {
            return;
        };
        let Ok(state) = serde_json::from_str::<serde_json::Value>(&body) else {
            return;
        };
        let existing_binary = self.pwn_view().binary.clone();
        let pwn = self.pwn_view_mut();
        pwn.state_snapshot = Some(state.clone());
        pwn.binary = state
            .pointer("/binary/path")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .or(existing_binary);
    }
}

fn path_value(result: &serde_json::Value, key: &str) -> Option<PathBuf> {
    result
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
}

pub(crate) fn latest_pwn_state_path(target: Option<&PathBuf>) -> Option<PathBuf> {
    let root = target.cloned().or_else(|| std::env::current_dir().ok())?;
    let pwn_dir = root.join(".kuzushi/pwn");
    let entries = std::fs::read_dir(pwn_dir).ok()?;
    let mut candidates = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("state.json"))
        .filter(|path| path.is_file())
        .filter_map(|path| {
            let modified = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok()?;
            Some((modified, path))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(modified, _)| *modified);
    candidates.pop().map(|(_, path)| path)
}
