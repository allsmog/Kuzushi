use super::*;

impl ShellApp {
    pub(crate) fn handle_pwn_command(&mut self, command: &PwnCommand) {
        self.shell_view = ShellView::Pwn;
        match command {
            PwnCommand::Show => {
                self.refresh_pwn_state_from_disk();
                self.log("pwn", "dashboard");
            }
            PwnCommand::Target(path) => {
                self.pwn_view.target = Some(path.clone());
                self.pwn_view.binary = Some(path.clone());
                self.refresh_pwn_state_from_disk();
                self.log("pwn", format!("target {}", path.display()));
            }
            PwnCommand::Profile => {
                if let Some(binary) = self.pwn_binary_for_command() {
                    self.run_pwn_tool(
                        "pwn:profile-binary",
                        serde_json::json!({ "binary": binary }),
                    );
                }
            }
            PwnCommand::Reverse(function) => {
                if let Some(binary) = self.pwn_binary_for_command() {
                    let mut input = serde_json::json!({ "binary": binary });
                    if let Some(function) = function {
                        input["function"] = serde_json::json!(function);
                    }
                    self.run_pwn_tool("pwn:reverse", input);
                }
            }
            PwnCommand::Auto => {
                if let Some(target) = self.pwn_target_for_command() {
                    self.run_pwn_tool("pwn:auto-solve", serde_json::json!({ "target": target }));
                }
            }
            PwnCommand::State => {
                if let Some(binary) = self.pwn_binary_for_command() {
                    self.run_pwn_tool("pwn:state", serde_json::json!({ "binary": binary }));
                }
            }
            PwnCommand::Candidates(target) => {
                let Some(state_id) = self.pwn_state_id_for_candidates() else {
                    self.log(
                        "error",
                        "pwn candidates needs a profiled binary/state first. Next: pwn profile",
                    );
                    return;
                };
                self.run_pwn_tool(
                    "pwn:run-candidates",
                    serde_json::json!({ "target": target, "stateId": state_id }),
                );
            }
            PwnCommand::Unsupported(verb) => {
                self.log(
                    "error",
                    format!("unknown pwn command {verb:?}. Next: pwn, pwn target <path>, pwn auto"),
                );
            }
        }
    }

    pub(crate) fn cache_pwn_snapshot(&mut self, tool_name: &str, result: &serde_json::Value) {
        match tool_name {
            "pwn:profile-binary" => {
                self.pwn_view.profile_snapshot = Some(result.clone());
                self.pwn_view.binary = result
                    .get("binary")
                    .and_then(serde_json::Value::as_str)
                    .map(PathBuf::from)
                    .or_else(|| self.pwn_view.binary.clone());
                self.pwn_view.state_path = result
                    .get("statePath")
                    .and_then(serde_json::Value::as_str)
                    .map(PathBuf::from)
                    .or_else(|| self.pwn_view.state_path.clone());
                self.refresh_pwn_state_from_disk();
            }
            "pwn:reverse" => {
                self.pwn_view.reverse_snapshots.push(result.clone());
                if self.pwn_view.reverse_snapshots.len() > 12 {
                    let overflow = self.pwn_view.reverse_snapshots.len() - 12;
                    self.pwn_view.reverse_snapshots.drain(0..overflow);
                }
            }
            "pwn:auto-solve" => {
                self.pwn_view.auto_solve_snapshot = Some(result.clone());
                self.pwn_view.state_path = result
                    .get("statePath")
                    .and_then(serde_json::Value::as_str)
                    .map(PathBuf::from)
                    .or_else(|| self.pwn_view.state_path.clone());
                self.refresh_pwn_state_from_disk();
            }
            "pwn:state" => {
                self.pwn_view.state_snapshot = Some(result.clone());
                self.pwn_view.state_path = result
                    .get("statePath")
                    .and_then(serde_json::Value::as_str)
                    .map(PathBuf::from)
                    .or_else(|| self.pwn_view.state_path.clone());
            }
            "pwn:run-candidates" => {
                self.pwn_view.candidates_snapshot = Some(result.clone());
                self.refresh_pwn_state_from_disk();
            }
            _ => {}
        }
    }

    fn run_pwn_tool(&mut self, tool_name: &str, input: serde_json::Value) {
        let input = match serde_json::to_string(&input) {
            Ok(input) => input,
            Err(error) => {
                self.log("error", format!("could not encode pwn tool input: {error}"));
                return;
            }
        };
        self.run_tool(Some(tool_name.to_string()), Some(input));
    }

    fn pwn_target_for_command(&mut self) -> Option<String> {
        self.pwn_view
            .target
            .as_ref()
            .or(self.pwn_view.binary.as_ref())
            .map(|path| path.display().to_string())
            .or_else(|| {
                self.log("error", "pwn target is not set. Next: pwn target <path>");
                None
            })
    }

    fn pwn_binary_for_command(&mut self) -> Option<String> {
        self.pwn_view
            .binary
            .as_ref()
            .or(self.pwn_view.target.as_ref())
            .map(|path| path.display().to_string())
            .or_else(|| {
                self.log("error", "pwn binary is not set. Next: pwn target <path>");
                None
            })
    }

    fn pwn_state_id_for_candidates(&mut self) -> Option<String> {
        self.pwn_view
            .state_snapshot
            .as_ref()
            .and_then(|state| state.get("stateId"))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                self.pwn_view
                    .profile_snapshot
                    .as_ref()
                    .and_then(|profile| profile.get("stateId"))
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            })
            .or_else(|| {
                self.pwn_view
                    .state_snapshot
                    .as_ref()
                    .and_then(|state| state.get("state"))
                    .and_then(|state| state.get("stateId"))
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            })
    }

    fn refresh_pwn_state_from_disk(&mut self) {
        if self.pwn_view.state_path.is_none() {
            self.pwn_view.state_path = latest_pwn_state_path(self.target.as_ref());
        }
        let Some(path) = self.pwn_view.state_path.clone() else {
            return;
        };
        let Ok(body) = std::fs::read_to_string(&path) else {
            return;
        };
        let Ok(state) = serde_json::from_str::<serde_json::Value>(&body) else {
            return;
        };
        self.pwn_view.state_snapshot = Some(state.clone());
        self.pwn_view.binary = state
            .pointer("/binary/path")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .or_else(|| self.pwn_view.binary.clone());
    }
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
