use super::*;

impl ShellApp {
    pub(crate) fn prompt_path_for(&self, name: &str) -> Option<PathBuf> {
        let module = self.focused_module()?;
        let target = self.target_owned()?;
        let safe = name.trim().replace(['/', '\\'], "");
        if safe.is_empty() {
            return None;
        }
        Some(kuzushi_core::prompt_override_path(target, module, &safe))
    }
}
