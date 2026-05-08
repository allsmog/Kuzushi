use super::*;

impl ShellApp {
    pub(crate) fn prompt_set(&mut self, args: &str) {
        let mut parts = args.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if name.is_empty() || value.is_empty() {
            self.log(
                "prompt",
                "set requires a name and quoted value: prompt set triage \"focus on auth\"",
            );
            return;
        }
        let value = value
            .strip_prefix('"')
            .and_then(|stripped| stripped.strip_suffix('"'))
            .unwrap_or(value);
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt set requires a focused module and workspace",
            );
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                self.log(
                    "error",
                    format!("could not create {}: {error}", parent.display()),
                );
                return;
            }
        }
        match std::fs::write(&path, value) {
            Ok(_) => self.log(
                "prompt",
                format!("wrote {} ({} bytes)", path.display(), value.len()),
            ),
            Err(error) => self.log(
                "error",
                format!("could not write {}: {error}", path.display()),
            ),
        }
    }
}
