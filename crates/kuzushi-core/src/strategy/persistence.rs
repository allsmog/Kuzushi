use crate::workspace::{
    ensure_workspace_output_dir, read_optional_workspace_text, remove_workspace_state_file,
    write_workspace_state_file, WorkspaceTarget, KUZUSHI_STATE_DIR, WORKSPACE_STATE_VERSION_DIR,
};
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_STRATEGY_LEDGER_BYTES: usize = 4 * 1024 * 1024;
const STRATEGY_LEDGER_LOCK: &str = ".strategy-ledger.lock";
const STRATEGY_TRANSACTION_FILE: &str = ".strategy-ledger-transaction.json";
const MAX_STRATEGY_TRANSACTION_BYTES: usize = MAX_STRATEGY_LEDGER_BYTES * 5;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StrategyLedgerTransaction {
    queue_body: String,
    corrections_body: String,
}

pub(super) fn strategy_state_path(workspace: &WorkspaceTarget, file_name: &str) -> PathBuf {
    workspace.state_dir().join(file_name)
}

pub(crate) fn acquire_strategy_ledger_lock(
    workspace: &WorkspaceTarget,
) -> Result<crate::file_lock::ExclusiveFileLock> {
    let state_dir = ensure_workspace_output_dir(
        workspace.root(),
        Path::new(KUZUSHI_STATE_DIR).join(WORKSPACE_STATE_VERSION_DIR),
    )?;
    crate::file_lock::ExclusiveFileLock::acquire(&state_dir.join(STRATEGY_LEDGER_LOCK))
}

pub(super) fn load_strategy_jsonl<T>(
    workspace: &WorkspaceTarget,
    file_name: &str,
    item_label: &str,
) -> Result<Vec<T>>
where
    T: DeserializeOwned,
{
    let path = strategy_state_path(workspace, file_name);
    let Some(text) =
        read_optional_workspace_text(workspace.root(), &path, MAX_STRATEGY_LEDGER_BYTES)?
    else {
        return Ok(Vec::new());
    };
    parse_jsonl(&text, item_label)
}

pub(super) fn save_strategy_jsonl<T>(
    workspace: &WorkspaceTarget,
    file_name: &str,
    values: &[T],
    item_label: &str,
) -> Result<()>
where
    T: Serialize,
{
    let body = serialize_jsonl(values, item_label)?;
    anyhow::ensure!(
        body.len() <= MAX_STRATEGY_LEDGER_BYTES,
        "{item_label} ledger exceeds the {MAX_STRATEGY_LEDGER_BYTES}-byte write limit"
    );
    write_strategy_jsonl_body(workspace, file_name, body.as_bytes())
}

pub(super) fn encode_strategy_jsonl<T>(values: &[T], item_label: &str) -> Result<String>
where
    T: Serialize,
{
    let body = serialize_jsonl(values, item_label)?;
    anyhow::ensure!(
        body.len() <= MAX_STRATEGY_LEDGER_BYTES,
        "{item_label} ledger exceeds the {MAX_STRATEGY_LEDGER_BYTES}-byte write limit"
    );
    Ok(body)
}

pub(super) fn write_strategy_jsonl_body(
    workspace: &WorkspaceTarget,
    file_name: &str,
    body: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        body.len() <= MAX_STRATEGY_LEDGER_BYTES,
        "strategy ledger exceeds the {MAX_STRATEGY_LEDGER_BYTES}-byte write limit"
    );
    let relative = Path::new(KUZUSHI_STATE_DIR)
        .join(WORKSPACE_STATE_VERSION_DIR)
        .join(file_name);
    write_workspace_state_file(workspace.root(), relative, body)?;
    Ok(())
}

pub(super) fn begin_strategy_transaction(
    workspace: &WorkspaceTarget,
    queue_body: String,
    corrections_body: String,
) -> Result<()> {
    let transaction = StrategyLedgerTransaction {
        queue_body,
        corrections_body,
    };
    let body =
        serde_json::to_vec(&transaction).context("Could not serialize strategy transaction")?;
    anyhow::ensure!(
        body.len() <= MAX_STRATEGY_TRANSACTION_BYTES,
        "strategy transaction exceeds the {MAX_STRATEGY_TRANSACTION_BYTES}-byte limit"
    );
    write_workspace_state_file(workspace.root(), transaction_relative_path(), &body)?;
    Ok(())
}

pub(super) fn recover_strategy_transaction(
    workspace: &WorkspaceTarget,
    queue_file: &str,
    corrections_file: &str,
) -> Result<()> {
    let path = workspace.state_dir().join(STRATEGY_TRANSACTION_FILE);
    let Some(body) =
        read_optional_workspace_text(workspace.root(), &path, MAX_STRATEGY_TRANSACTION_BYTES)?
    else {
        return Ok(());
    };
    let transaction: StrategyLedgerTransaction =
        serde_json::from_str(&body).context("Could not parse pending strategy transaction")?;
    write_strategy_jsonl_body(
        workspace,
        corrections_file,
        transaction.corrections_body.as_bytes(),
    )?;
    write_strategy_jsonl_body(workspace, queue_file, transaction.queue_body.as_bytes())?;
    clear_strategy_transaction(workspace)
}

pub(super) fn clear_strategy_transaction(workspace: &WorkspaceTarget) -> Result<()> {
    remove_workspace_state_file(workspace.root(), transaction_relative_path())?;
    Ok(())
}

fn transaction_relative_path() -> PathBuf {
    Path::new(KUZUSHI_STATE_DIR)
        .join(WORKSPACE_STATE_VERSION_DIR)
        .join(STRATEGY_TRANSACTION_FILE)
}

fn parse_jsonl<T>(text: &str, item_label: &str) -> Result<Vec<T>>
where
    T: DeserializeOwned,
{
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<T>(line)
                .with_context(|| format!("Could not parse {item_label} line {}", index + 1))
        })
        .collect()
}

fn serialize_jsonl<T>(values: &[T], item_label: &str) -> Result<String>
where
    T: Serialize,
{
    let mut lines = Vec::with_capacity(values.len());
    for value in values {
        lines.push(
            serde_json::to_string(value)
                .with_context(|| format!("Could not serialize {item_label}"))?,
        );
    }
    if lines.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("{}\n", lines.join("\n")))
    }
}
