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
    let max_agent_steps = read_u32(input, &["maxAgentSteps", "max_agent_steps"], 120, 4).min(400);
    let clang_call_timeout_secs = read_u64(input, &["clangTimeoutSecs"], 60, 5).min(300);
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
        model,
    })
}

/// Resolve `compile_commands.json` precedence:
///   1. Explicit `compileCommandsPath` input field
///   2. `<target>/compile_commands.json`
///   3. `<target>/build/compile_commands.json`
///
/// Bails loudly when none exist — uaf-hunt is useless without a clangd
/// index, and silently degrading to grep-only would defeat the module.
pub(crate) fn resolve_compile_commands_path(input: &Value, target: &Path) -> Result<PathBuf> {
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
        return Ok(resolved);
    }
    for relative in ["compile_commands.json", "build/compile_commands.json"] {
        let candidate = target.join(relative);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "uaf-hunt:hunt requires a clangd-compatible compile_commands.json under {target}. \
         Generate one with `bear -- make` (Make-based projects like Redis) or by re-running \
         cmake with `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` and symlinking \
         `build/compile_commands.json` to the workspace root. Pass an explicit path via the \
         `compileCommandsPath` input field if the file lives elsewhere.",
        target = target.display(),
    )
}

fn resolve_alloc_free_pairs(input: &Value) -> Result<Vec<AllocFreePair>> {
    if let Some(explicit) = input.get("allocFreePairs").and_then(Value::as_array) {
        let pairs = parse_pair_array(explicit, "allocFreePairs")?;
        if pairs.is_empty() {
            anyhow::bail!(
                "uaf-hunt:hunt: `allocFreePairs` was empty; remove the key to use the defaults \
                 (malloc/free, calloc/free, realloc/free, strdup/free, strndup/free) or pass at \
                 least one {{\"alloc\":\"...\",\"free\":\"...\"}} entry."
            );
        }
        return Ok(pairs);
    }
    let mut pairs = default_alloc_free_pairs();
    if let Some(extras) = input.get("extraAllocFreePairs").and_then(Value::as_array) {
        let parsed = parse_pair_array(extras, "extraAllocFreePairs")?;
        for pair in parsed {
            if !pairs.iter().any(|existing| existing == &pair) {
                pairs.push(pair);
            }
        }
    }
    Ok(pairs)
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
