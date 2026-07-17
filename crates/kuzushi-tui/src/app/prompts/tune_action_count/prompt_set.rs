use super::*;
use anyhow::Context;
use std::path::Path;

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
        let Some(target) = self.target_path_buf().cloned() else {
            self.log("error", "could not write prompt override without a target");
            return;
        };
        match write_prompt_override(&target, &write) {
            Ok(_) => {
                self.invalidate_prompt_view_cache();
                self.finish_prompt_document_write(&write.path, &write.value);
                self.log(
                    "prompt",
                    format!(
                        "wrote {} ({} bytes)",
                        write.path.display(),
                        write.value.len()
                    ),
                );
            }
            Err(error) => self.log(
                "prompt",
                format!(
                    "could not set override at {}: {error}",
                    write.path.display()
                ),
            ),
        }
    }
}

fn write_prompt_override(target: &Path, write: &PromptOverrideWrite) -> anyhow::Result<()> {
    let relative = write.path.strip_prefix(target).with_context(|| {
        format!(
            "prompt override {} is outside the target",
            write.path.display()
        )
    })?;
    kuzushi_core::workspace::read_optional_workspace_text(target, &write.path, 1024 * 1024)?;
    kuzushi_core::workspace::write_workspace_state_file(target, relative, write.value.as_bytes())
        .map(|_| ())
}

fn prompt_set_args(args: &str) -> Option<(&str, &str)> {
    let mut parts = args.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("").trim();
    let value = parts.next().unwrap_or("").trim();
    if name.is_empty() || value.is_empty() {
        return None;
    }
    let value = unquote_prompt_set_value(value);
    (!value.trim().is_empty()).then_some((name, value))
}

fn unquote_prompt_set_value(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|stripped| stripped.strip_suffix('"'))
        .unwrap_or(value)
}
