use crate::capabilities::uaf_hunt::domain::{
    default_alloc_free_pairs, AllocFreePair, UafHuntInput,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub(crate) fn parse_uaf_hunt_input(input: &Value, target: &Path) -> Result<UafHuntInput> {
    let compile_commands_path = resolve_compile_commands_path(input, target)?;
    let alloc_free_pairs = resolve_alloc_free_pairs(input)?;
    let max_findings = read_usize(input, &["maxFindings", "max_findings"], 30, 1).min(500);
    // Default was 60; bumped to 120 after the first live run hit the cap
    // at 85 steps with a single alloc/free pair on a 200-file C codebase.
    // Tool-augmented hunts on real codebases routinely need 80-150 steps
    // before the model converges on a structured Final.
    let max_agent_steps = read_u32(input, &["maxAgentSteps", "max_agent_steps"], 120, 1).min(400);
    let clang_call_timeout_secs =
        read_u64(input, &["clangTimeoutSecs", "clang_timeout_secs"], 60, 1).min(300);
    let include_non_production = read_bool(
        input,
        &["includeNonProduction", "include_non_production"],
        false,
    );
    let model = input
        .get("model")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Ok(UafHuntInput {
        max_findings,
        max_agent_steps,
        alloc_free_pairs,
        compile_commands_path,
        clang_call_timeout_secs,
        include_non_production,
        model,
    })
}

/// Resolve `compile_commands.json` precedence:
///   1. Explicit workspace `compileCommandsPath` or operator-owned `externalCompileCommandsPath`
///   2. `<target>/compile_commands.json`
///   3. `<target>/build/compile_commands.json`
///
/// Bails loudly when none exist — uaf-hunt is useless without a clangd
/// index, and silently degrading to grep-only would defeat the module.
pub(crate) fn resolve_compile_commands_path(input: &Value, target: &Path) -> Result<PathBuf> {
    if let Some(path) = external_compile_commands_path(input)? {
        return Ok(path);
    }
    if let Some(path) = workspace_compile_commands_path(input, target)? {
        return Ok(path);
    }
    if let Some(path) = default_compile_commands_path(target) {
        return Ok(path);
    }
    anyhow::bail!(
        "uaf-hunt:hunt requires an existing compiler database in compile_commands.json format for {target}. \
         Select a workspace file with compileCommandsPath or an operator-owned out-of-tree \
         file with externalCompileCommandsPath. Kuzushi does not build the target or run \
         compiler-driver probes. For CMake, prepare one separately with -DCMAKE_EXPORT_COMPILE_COMMANDS=ON.",
        target = target.display(),
    )
}

fn default_compile_commands_path(target: &Path) -> Option<PathBuf> {
    for relative in ["compile_commands.json", "build/compile_commands.json"] {
        let candidate = target.join(relative);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn external_compile_commands_path(input: &Value) -> Result<Option<PathBuf>> {
    if let Some(external) = input
        .get("externalCompileCommandsPath")
        .and_then(Value::as_str)
    {
        anyhow::ensure!(
            input.get("compileCommandsPath").is_none(),
            "choose compileCommandsPath or externalCompileCommandsPath, not both"
        );
        anyhow::ensure!(
            !external.is_empty(),
            "externalCompileCommandsPath must not be empty"
        );
        return Ok(Some(PathBuf::from(external)));
    }
    Ok(None)
}

fn workspace_compile_commands_path(input: &Value, target: &Path) -> Result<Option<PathBuf>> {
    if let Some(explicit) = input
        .get("compileCommandsPath")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        let path = PathBuf::from(explicit);
        let resolved = if path.is_absolute() {
            path
        } else {
            target.join(path)
        };
        if !resolved.exists() {
            anyhow::bail!(
                "uaf-hunt:hunt: compileCommandsPath {} does not exist",
                resolved.display()
            );
        }
        return Ok(Some(resolved));
    }
    Ok(None)
}

fn resolve_alloc_free_pairs(input: &Value) -> Result<Vec<AllocFreePair>> {
    if let Some(explicit) = input.get("allocFreePairs") {
        return replacement_alloc_free_pairs(explicit);
    }
    let mut pairs = default_alloc_free_pairs();
    if let Some(extras) = input.get("extraAllocFreePairs") {
        extend_unique_pairs(&mut pairs, parse_pair_value(extras, "extraAllocFreePairs")?);
    }
    Ok(pairs)
}

fn replacement_alloc_free_pairs(value: &Value) -> Result<Vec<AllocFreePair>> {
    let pairs = parse_pair_value(value, "allocFreePairs")?;
    anyhow::ensure!(
        !pairs.is_empty(),
        "uaf-hunt:hunt: `allocFreePairs` was empty; omit it to use the default pairs, or supply at least one allocation/free pair."
    );
    Ok(pairs)
}

fn extend_unique_pairs(pairs: &mut Vec<AllocFreePair>, extras: Vec<AllocFreePair>) {
    for pair in extras {
        if !pairs.contains(&pair) {
            pairs.push(pair);
        }
    }
}

fn parse_pair_value(value: &Value, field: &str) -> Result<Vec<AllocFreePair>> {
    let items = value.as_array().with_context(|| {
        format!("uaf-hunt: `{field}` must be an array of {{alloc, free}} objects")
    })?;
    parse_pair_array(items, field)
}

fn parse_pair_array(items: &[Value], field: &str) -> Result<Vec<AllocFreePair>> {
    items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let alloc = item
                .get("alloc")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .with_context(|| {
                    format!("uaf-hunt: `{field}[{idx}].alloc` must be a non-empty string")
                })?
                .to_string();
            let free = item
                .get("free")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .with_context(|| {
                    format!("uaf-hunt: `{field}[{idx}].free` must be a non-empty string")
                })?
                .to_string();
            Ok(AllocFreePair { alloc, free })
        })
        .collect()
}

fn read_usize(input: &Value, keys: &[&str], default: usize, min: usize) -> usize {
    for key in keys {
        if let Some(value) = input.get(key).and_then(Value::as_u64) {
            return (value as usize).max(min);
        }
    }
    default
}

fn read_u32(input: &Value, keys: &[&str], default: u32, min: u32) -> u32 {
    for key in keys {
        if let Some(value) = input.get(key).and_then(Value::as_u64) {
            return (value as u32).max(min);
        }
    }
    default
}

fn read_u64(input: &Value, keys: &[&str], default: u64, min: u64) -> u64 {
    for key in keys {
        if let Some(value) = input.get(key).and_then(Value::as_u64) {
            return value.max(min);
        }
    }
    default
}

fn read_bool(input: &Value, keys: &[&str], default: bool) -> bool {
    for key in keys {
        if let Some(value) = input.get(key).and_then(Value::as_bool) {
            return value;
        }
    }
    default
}
