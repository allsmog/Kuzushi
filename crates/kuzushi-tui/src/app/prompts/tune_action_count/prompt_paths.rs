use super::*;
use std::path::Path;

impl ShellApp {
    pub(crate) fn prompt_path_for(&self, name: &str) -> Option<PathBuf> {
        let module = self.focused_module()?;
        let target = self.target_owned()?;
        let safe = name.trim();
        if !valid_prompt_override_name(safe) {
            return None;
        }
        Some(kuzushi_core::prompt_override_path(target, module, safe))
    }
}

fn valid_prompt_override_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 128
        || matches!(name, "." | "..")
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return false;
    }
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}
