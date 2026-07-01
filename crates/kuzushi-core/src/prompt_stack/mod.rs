use crate::fs_atomic::write_atomic;
use crate::options::prompt_content_sha256;
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROMPT_MUTATIONS_FILE: &str = "prompt-mutations.jsonl";

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
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not read {}", path.display()))
        }
    };
    parse_prompt_mutations_jsonl(&text).with_context(|| format!("Could not parse {}", path.display()))
}

pub fn save_prompt_mutations(
    workspace: &WorkspaceTarget,
    mutations: &[PromptMutation],
) -> Result<()> {
    write_atomic(
        &prompt_mutations_path(workspace),
        &serialize_prompt_mutations_jsonl(mutations)?,
    )
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
    let mut mutations = load_prompt_mutations(workspace)?;
    let Some(mutation) = mutations.iter_mut().find(|mutation| mutation.id == id) else {
        return Ok(false);
    };
    mutation.status = status;
    mutation.reason = reason
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    mutation.updated_at_ms = now_ms();
    save_prompt_mutations(workspace, &mutations)?;
    Ok(true)
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

fn parse_prompt_mutations_jsonl(text: &str) -> Result<Vec<PromptMutation>> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<PromptMutation>(line).with_context(|| format!("line {}", index + 1))
        })
        .collect()
}

fn serialize_prompt_mutations_jsonl(mutations: &[PromptMutation]) -> Result<String> {
    let mut lines = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        lines.push(serde_json::to_string(mutation).context("Could not serialize prompt mutation")?);
    }
    Ok(if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    })
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
        slug_part(module_id),
        slug_part(verb)
    )
}

fn slug_part(value: &str) -> String {
    let slug = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .take(4)
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() {
        "prompt".to_string()
    } else {
        slug
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_mutations_round_trip_and_status_gate() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mutation =
            PromptMutation::new("sast", "triage", "focus authz paths", "operator");

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
        assert_eq!(loaded.content_hash(), prompt_content_sha256("focus authz paths"));
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
}
