use super::{MAX_COMPILE_COMMANDS, MAX_COMPILE_DATABASE_BYTES};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(super) fn prepare(source: &Path, raw: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut commands: Vec<Value> = serde_json::from_slice(raw)
        .context("compiler database must be a JSON array of compile commands")?;
    anyhow::ensure!(
        commands.len() <= MAX_COMPILE_COMMANDS,
        "compiler database exceeds 100000 commands"
    );
    let base = source
        .parent()
        .context("compiler database has no parent directory")?;
    for (index, command) in commands.iter_mut().enumerate() {
        bind_command(command, base).with_context(|| format!("invalid compile command {index}"))?;
    }
    let prepared = serde_json::to_vec(&commands)?;
    anyhow::ensure!(
        prepared.len() <= MAX_COMPILE_DATABASE_BYTES,
        "prepared compiler database exceeds 8 MiB"
    );
    Ok((prepared, commands.len()))
}

fn bind_command(command: &mut Value, base: &Path) -> Result<()> {
    let directory = required_text(command, "directory")?;
    let directory = Path::new(directory);
    let bound = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        base.join(directory)
    };
    required_text(command, "file")?;
    validate_arguments(command)?;
    command["directory"] = serde_json::to_value(bound)?;
    Ok(())
}

fn required_text<'a>(command: &'a Value, name: &str) -> Result<&'a str> {
    command
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .with_context(|| format!("compile command requires nonempty {name}"))
}

fn validate_arguments(command: &Value) -> Result<()> {
    let Some(arguments) = command.get("arguments") else {
        required_text(command, "command")?;
        return Ok(());
    };
    let arguments = arguments
        .as_array()
        .context("compile arguments must be an array")?;
    anyhow::ensure!(!arguments.is_empty(), "compile arguments must not be empty");
    anyhow::ensure!(
        arguments.iter().all(valid_argument),
        "compile arguments must be strings without NUL bytes"
    );
    Ok(())
}

fn valid_argument(argument: &Value) -> bool {
    argument.as_str().is_some_and(|value| !value.contains('\0'))
}
