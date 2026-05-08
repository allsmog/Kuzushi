use super::*;

impl ShellApp {
    pub(crate) fn prompt_path_for(&self, name: &str) -> Option<PathBuf> {
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
}
