use super::*;

impl ShellApp {
    pub(crate) fn prompt_list(&mut self) {
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
