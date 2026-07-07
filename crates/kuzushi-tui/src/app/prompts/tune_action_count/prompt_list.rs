use super::*;

impl ShellApp {
    pub(crate) fn reduce_prompt_list(&mut self) -> Vec<ShellEffect> {
        let Some((module, target)) = self.prompt_list_scope() else {
            return Vec::new();
        };
        let dir = kuzushi_core::module_prompt_root(target, &module);
        vec![ShellEffect::ListPromptOverrides(PromptOverrideList { dir })]
    }

    pub(crate) fn list_prompt_overrides_effect(&mut self, list: PromptOverrideList) {
        let dir = list.dir;
        if !dir.exists() {
            self.log_missing_prompt_override_dir(&dir);
            return;
        }
        let names = match prompt_override_names(&dir) {
            Ok(names) => names,
            Err(error) => {
                self.log_unreadable_prompt_override_dir(&dir, &error);
                return;
            }
        };
        self.log_prompt_override_names(&dir, names);
    }

    fn prompt_list_scope(&mut self) -> Option<(String, std::path::PathBuf)> {
        let module = self.focused_module_owned().or_else(|| {
            self.log(
                "prompt",
                "list requires a focused module. Next: /use <module>",
            );
            None
        })?;
        let target = self.target_owned().or_else(|| {
            self.log("prompt", "list requires a workspace target");
            None
        })?;
        Some((module, target))
    }

    fn log_prompt_override_names(&mut self, dir: &std::path::Path, names: Vec<String>) {
        if names.is_empty() {
            self.log("prompt", format!("no overrides in {}", dir.display()));
        } else {
            self.log("prompt", format!("overrides in {}:", dir.display()));
            for name in names {
                self.log("prompt", format!("  - {name}"));
            }
        }
    }

    fn log_missing_prompt_override_dir(&mut self, dir: &std::path::Path) {
        self.log(
            "prompt",
            format!("no override directory at {}", dir.display()),
        );
    }

    fn log_unreadable_prompt_override_dir(
        &mut self,
        dir: &std::path::Path,
        error: &std::io::Error,
    ) {
        self.log(
            "prompt",
            format!(
                "could not read override directory at {}: {error}",
                dir.display()
            ),
        );
    }
}

fn prompt_override_names(dir: &std::path::Path) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        if let Some(name) = prompt_override_name(entry?) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn prompt_override_name(entry: std::fs::DirEntry) -> Option<String> {
    entry
        .file_name()
        .into_string()
        .ok()
        .and_then(|name| name.strip_suffix(".md").map(str::to_string))
}
