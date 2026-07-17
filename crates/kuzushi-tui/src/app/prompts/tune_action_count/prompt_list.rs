use super::*;

const MAX_PROMPT_OVERRIDE_ENTRIES: usize = 1024;

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
        let Some(target) = self.target_owned() else {
            self.log("error", "could not list prompt overrides without a target");
            return;
        };
        let names = match prompt_override_names(&target, &dir) {
            Ok(Some(names)) => names,
            Ok(None) => {
                self.log_missing_prompt_override_dir(&dir);
                return;
            }
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

    fn log_unreadable_prompt_override_dir(&mut self, dir: &std::path::Path, error: &str) {
        self.log(
            "prompt",
            format!(
                "could not read override directory at {}: {error}",
                dir.display()
            ),
        );
    }
}

fn prompt_override_names(
    target: &std::path::Path,
    dir: &std::path::Path,
) -> Result<Option<Vec<String>>, String> {
    let Some(dir) = checked_prompt_override_directory(target, dir)? else {
        return Ok(None);
    };
    let mut names = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|error| error.to_string())?;
    for (index, entry) in entries.take(MAX_PROMPT_OVERRIDE_ENTRIES + 1).enumerate() {
        if index == MAX_PROMPT_OVERRIDE_ENTRIES {
            return Err(format!(
                "prompt override directory exceeds {MAX_PROMPT_OVERRIDE_ENTRIES} entries"
            ));
        }
        let entry = entry.map_err(|error| error.to_string())?;
        if let Some(name) = prompt_override_name(entry)? {
            names.push(name);
        }
    }
    names.sort();
    Ok(Some(names))
}

fn checked_prompt_override_directory(
    target: &std::path::Path,
    dir: &std::path::Path,
) -> Result<Option<std::path::PathBuf>, String> {
    let expected = expected_prompt_override_directory(target, dir)?;
    resolve_prompt_override_directory(expected)
}

fn expected_prompt_override_directory(
    target: &std::path::Path,
    dir: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let root = std::fs::canonicalize(target).map_err(|error| error.to_string())?;
    let relative = dir
        .strip_prefix(target)
        .map_err(|_| format!("{} is outside target", dir.display()))?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "invalid prompt override directory {}",
            dir.display()
        ));
    }
    Ok(root.join(relative))
}

fn resolve_prompt_override_directory(
    expected: std::path::PathBuf,
) -> Result<Option<std::path::PathBuf>, String> {
    let resolved = match std::fs::canonicalize(&expected) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    if resolved != expected {
        return Err(format!(
            "prompt override directory contains a symlink: {}",
            expected.display()
        ));
    }
    if !resolved.is_dir() {
        return Err(format!(
            "prompt override path is not a directory: {}",
            resolved.display()
        ));
    }
    Ok(Some(resolved))
}

fn prompt_override_name(entry: std::fs::DirEntry) -> Result<Option<String>, String> {
    if !entry
        .file_type()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Ok(None);
    }
    Ok(entry
        .file_name()
        .into_string()
        .ok()
        .and_then(|name| name.strip_suffix(".md").map(str::to_string)))
}
