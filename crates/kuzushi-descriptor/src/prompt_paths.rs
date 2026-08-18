use std::path::{Path, PathBuf};

// Pure relative prompt paths shared by descriptor consumers.

pub const PROMPTS_DIR: &str = "prompts";

pub fn relative_prompt_overrides_root() -> PathBuf {
    Path::new(".kuzushi").join(PROMPTS_DIR)
}

pub fn relative_module_prompt_root(module: &str) -> PathBuf {
    relative_prompt_overrides_root().join(module)
}

pub fn relative_prompt_override_path(module: &str, verb: &str) -> PathBuf {
    relative_module_prompt_root(module).join(format!("{verb}.md"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_prompt_paths_use_the_workspace_state_directory() {
        assert_eq!(
            relative_prompt_override_path("triage", "run"),
            Path::new(".kuzushi")
                .join(PROMPTS_DIR)
                .join("triage")
                .join("run.md")
        );
    }
}
