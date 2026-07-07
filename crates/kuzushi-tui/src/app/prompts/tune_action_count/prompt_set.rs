use super::*;

impl ShellApp {
    pub(crate) fn reduce_prompt_set(&mut self, args: &str) -> Vec<ShellEffect> {
        let Some((name, value)) = prompt_set_args(args) else {
            self.log(
                "prompt",
                "set requires a name and quoted value: prompt set triage \"focus on auth\"",
            );
            return Vec::new();
        };
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt set requires a focused module and workspace",
            );
            return Vec::new();
        };
        vec![ShellEffect::WritePromptOverride(PromptOverrideWrite {
            path,
            value: value.to_string(),
        })]
    }

    pub(crate) fn write_prompt_override_effect(&mut self, write: PromptOverrideWrite) {
        if !self.prepare_prompt_set_path(&write.path) {
            return;
        }
        match std::fs::write(&write.path, &write.value) {
            Ok(_) => self.log(
                "prompt",
                format!(
                    "wrote {} ({} bytes)",
                    write.path.display(),
                    write.value.len()
                ),
            ),
            Err(error) => self.log(
                "error",
                format!("could not write {}: {error}", write.path.display()),
            ),
        }
    }

    fn prepare_prompt_set_path(&mut self, path: &std::path::Path) -> bool {
        if !self.ensure_prompt_set_parent(path) {
            return false;
        }
        match prompt_set_path_state(path) {
            PromptSetPathState::FileOrMissing => true,
            PromptSetPathState::Unreadable => {
                self.log(
                    "prompt",
                    format!("could not set unreadable override at {}", path.display()),
                );
                false
            }
        }
    }

    fn ensure_prompt_set_parent(&mut self, path: &std::path::Path) -> bool {
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
}

fn prompt_set_args(args: &str) -> Option<(&str, &str)> {
    let mut parts = args.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("").trim();
    let value = parts.next().unwrap_or("").trim();
    if name.is_empty() || value.is_empty() {
        return None;
    }
    Some((name, unquote_prompt_set_value(value)))
}

fn unquote_prompt_set_value(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|stripped| stripped.strip_suffix('"'))
        .unwrap_or(value)
}

enum PromptSetPathState {
    FileOrMissing,
    Unreadable,
}

fn prompt_set_path_state(path: &std::path::Path) -> PromptSetPathState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => PromptSetPathState::FileOrMissing,
        Ok(_) => PromptSetPathState::Unreadable,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PromptSetPathState::FileOrMissing
        }
        Err(_) => PromptSetPathState::Unreadable,
    }
}
