use crate::fs_atomic::{now_ms, slug};
#[cfg(test)]
use crate::options::prompt_override_path;
use crate::options::{prompt_content_sha256, relative_prompt_override_path};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const PROMPT_MUTATIONS_FILE: &str = "prompt-mutations.jsonl";
const MAX_PROMPT_MUTATIONS_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PromptMutation {
    pub id: String,
    pub module_id: String,
    pub verb: String,
    pub text: String,
    pub status: PromptMutationStatus,
    pub reason: Option<String>,
    pub author: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PromptMutationStatus {
    Pending,
    Approved,
    Rejected,
}

impl PromptMutationStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

impl PromptMutation {
    pub fn new(
        module_id: impl Into<String>,
        verb: impl Into<String>,
        text: impl Into<String>,
        author: impl Into<String>,
    ) -> Self {
        let now = now_ms();
        Self::new_at(now, module_id, verb, text, author)
    }

    pub fn new_at(
        now: u64,
        module_id: impl Into<String>,
        verb: impl Into<String>,
        text: impl Into<String>,
        author: impl Into<String>,
    ) -> Self {
        let module_id = module_id.into();
        let verb = verb.into();
        let text = text.into();
        Self {
            id: prompt_mutation_id(&module_id, &verb, &text, now),
            module_id,
            verb,
            text,
            status: PromptMutationStatus::Pending,
            reason: None,
            author: author.into(),
            created_at_ms: now,
            updated_at_ms: now,
        }
    }

    pub fn content_hash(&self) -> String {
        prompt_content_sha256(&self.text)
    }
}

pub fn prompt_mutations_path(workspace: &WorkspaceTarget) -> PathBuf {
    workspace.state_dir().join(PROMPT_MUTATIONS_FILE)
}

pub fn load_prompt_mutations(workspace: &WorkspaceTarget) -> Result<Vec<PromptMutation>> {
    let path = prompt_mutations_path(workspace);
    let Some(text) = crate::workspace::read_optional_workspace_text(
        workspace.root(),
        &path,
        MAX_PROMPT_MUTATIONS_BYTES,
    )?
    else {
        return Ok(Vec::new());
    };
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("Could not parse prompt mutation line {}", index + 1))
        })
        .collect()
}

pub fn save_prompt_mutations(
    workspace: &WorkspaceTarget,
    mutations: &[PromptMutation],
) -> Result<()> {
    let mut lines = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        lines.push(serde_json::to_string(mutation).context("Could not serialize prompt mutation")?);
    }
    let body = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    let path = prompt_mutations_path(workspace);
    let relative = path
        .strip_prefix(workspace.root())
        .context("Prompt mutation path escaped the workspace")?;
    crate::workspace::write_workspace_state_file(workspace.root(), relative, body.as_bytes())?;
    Ok(())
}

pub fn append_prompt_mutation(
    workspace: &WorkspaceTarget,
    mutation: &PromptMutation,
) -> Result<()> {
    let mut mutations = load_prompt_mutations(workspace)?;
    mutations.push(mutation.clone());
    save_prompt_mutations(workspace, &mutations)
}

pub fn set_prompt_mutation_status(
    workspace: &WorkspaceTarget,
    id: &str,
    status: PromptMutationStatus,
    reason: Option<&str>,
) -> Result<bool> {
    if status == PromptMutationStatus::Approved {
        return Ok(approve_prompt_mutation(workspace, id, reason)?.is_some());
    }
    update_prompt_mutation_status(workspace, id, status, reason).map(|mutation| mutation.is_some())
}

pub fn approve_prompt_mutation(
    workspace: &WorkspaceTarget,
    id: &str,
    reason: Option<&str>,
) -> Result<Option<PromptMutation>> {
    let mut mutations = load_prompt_mutations(workspace)?;
    let Some(index) = mutations.iter().position(|mutation| mutation.id == id) else {
        return Ok(None);
    };
    let mut mutation = mutations[index].clone();
    mutation.apply_status(PromptMutationStatus::Approved, reason);
    write_prompt_override(workspace, &mutation)?;
    mutations[index] = mutation.clone();
    save_prompt_mutations(workspace, &mutations)?;
    Ok(Some(mutation))
}

fn update_prompt_mutation_status(
    workspace: &WorkspaceTarget,
    id: &str,
    status: PromptMutationStatus,
    reason: Option<&str>,
) -> Result<Option<PromptMutation>> {
    let mut mutations = load_prompt_mutations(workspace)?;
    let Some(mutation) = mutations.iter_mut().find(|mutation| mutation.id == id) else {
        return Ok(None);
    };
    mutation.apply_status(status, reason);
    let updated = mutation.clone();
    save_prompt_mutations(workspace, &mutations)?;
    Ok(Some(updated))
}

fn write_prompt_override(workspace: &WorkspaceTarget, mutation: &PromptMutation) -> Result<()> {
    crate::workspace::write_workspace_state_file(
        workspace.root(),
        relative_prompt_override_path(&mutation.module_id, &mutation.verb),
        mutation.text.as_bytes(),
    )
    .map(|_| ())
}

impl PromptMutation {
    fn apply_status(&mut self, status: PromptMutationStatus, reason: Option<&str>) {
        self.status = status;
        self.reason = reason
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        self.updated_at_ms = now_ms();
    }
}

pub fn latest_prompt_mutation(
    workspace: &WorkspaceTarget,
    module_id: &str,
    verb: &str,
) -> Result<Option<PromptMutation>> {
    Ok(load_prompt_mutations(workspace)?
        .into_iter()
        .rev()
        .find(|mutation| mutation.module_id == module_id && mutation.verb == verb))
}

fn prompt_mutation_id(module_id: &str, verb: &str, text: &str, now: u64) -> String {
    let hash = prompt_content_sha256(text)
        .strip_prefix("sha256:")
        .unwrap_or("prompt")
        .chars()
        .take(12)
        .collect::<String>();
    format!(
        "prompt-mutation-{}-{}-{now}-{hash}",
        slug(module_id, "prompt", 4),
        slug(verb, "prompt", 4)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_mutations_round_trip_and_status_gate() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mutation = PromptMutation::new("sast", "triage", "focus authz paths", "operator");

        append_prompt_mutation(&workspace, &mutation).unwrap();
        assert_eq!(
            latest_prompt_mutation(&workspace, "sast", "triage")
                .unwrap()
                .unwrap()
                .status,
            PromptMutationStatus::Pending
        );

        assert!(set_prompt_mutation_status(
            &workspace,
            &mutation.id,
            PromptMutationStatus::Approved,
            Some("reviewed stack")
        )
        .unwrap());
        let loaded = latest_prompt_mutation(&workspace, "sast", "triage")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.status, PromptMutationStatus::Approved);
        assert_eq!(loaded.reason.as_deref(), Some("reviewed stack"));
        assert_eq!(
            loaded.content_hash(),
            prompt_content_sha256("focus authz paths")
        );
        assert_eq!(
            std::fs::read_to_string(prompt_override_path(workspace.root(), "sast", "triage"))
                .unwrap(),
            "focus authz paths"
        );
    }

    #[test]
    fn prompt_mutation_status_update_reports_missing_id() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();

        assert!(!set_prompt_mutation_status(
            &workspace,
            "missing",
            PromptMutationStatus::Rejected,
            None
        )
        .unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn prompt_mutation_store_rejects_an_outside_symlink_for_reads_and_writes() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "OUTSIDE_PROMPT_STACK_TOKEN").unwrap();
        workspace.ensure_state_dir().unwrap();
        symlink(outside.path(), prompt_mutations_path(&workspace)).unwrap();

        let read_error = load_prompt_mutations(&workspace).unwrap_err().to_string();
        let write_error = save_prompt_mutations(&workspace, &[])
            .unwrap_err()
            .to_string();

        assert!(read_error.contains("symlink"), "{read_error}");
        assert!(write_error.contains("symlink"), "{write_error}");
        assert!(!read_error.contains("OUTSIDE_PROMPT_STACK_TOKEN"));
        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "OUTSIDE_PROMPT_STACK_TOKEN"
        );
    }
}
