use std::path::{Path, PathBuf};

pub use kuzushi_descriptor::prompt_paths::{
    PROMPTS_DIR, relative_module_prompt_root, relative_prompt_override_path,
    relative_prompt_overrides_root,
};

pub const HOUSE_RULES_DIR: &str = "house-rules";

pub fn prompt_overrides_root(target: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(PROMPTS_DIR)
}

pub fn module_prompt_root(target: impl AsRef<Path>, module: &str) -> PathBuf {
    prompt_overrides_root(target).join(module)
}

pub fn prompt_override_path(target: impl AsRef<Path>, module: &str, verb: &str) -> PathBuf {
    module_prompt_root(target, module).join(format!("{verb}.md"))
}

pub fn house_rules_root(target: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(HOUSE_RULES_DIR)
}

pub fn house_rule_path(target: impl AsRef<Path>, module: &str) -> PathBuf {
    house_rules_root(target).join(format!("{module}.md"))
}

pub fn relative_house_rules_root() -> PathBuf {
    Path::new(".kuzushi").join(HOUSE_RULES_DIR)
}

pub fn relative_house_rule_path(module: &str) -> PathBuf {
    relative_house_rules_root().join(format!("{module}.md"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_paths_use_workspace_state_root() {
        let target = Path::new("/repo");
        let state_root = crate::workspace::workspace_state_root(target);

        assert_eq!(
            prompt_override_path(target, "triage", "run"),
            state_root
                .join(PROMPTS_DIR)
                .join("triage")
                .join("run.md")
        );
        assert_eq!(
            house_rule_path(target, "sast"),
            state_root.join(HOUSE_RULES_DIR).join("sast.md")
        );
    }
}
