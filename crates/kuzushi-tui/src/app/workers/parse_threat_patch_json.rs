use super::*;

pub(crate) fn parse_threat_patch_json(goal: &str, body: &str) -> Result<ThreatPatch> {
    let json_start = body
        .find('{')
        .context("threat-patch response had no JSON object")?;
    let json_end = body
        .rfind('}')
        .context("threat-patch response had no closing JSON brace")?;
    if json_end <= json_start {
        anyhow::bail!("threat-patch response had unbalanced JSON");
    }
    let json_slice = &body[json_start..=json_end];
    let parsed: serde_json::Value =
        serde_json::from_str(json_slice).context("threat-patch JSON did not parse")?;
    let summary = parsed
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(goal)
        .to_string();
    let patch = parsed
        .get("patch")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if !matches!(
        patch,
        serde_json::Value::Object(_) | serde_json::Value::Null
    ) {
        anyhow::bail!("threat-patch must be a JSON object");
    }
    let unsupported = parsed
        .get("unsupported")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(ThreatPatch {
        goal: goal.to_string(),
        summary,
        patch,
        unsupported,
    })
}

pub(crate) fn merge_json(target: &mut serde_json::Value, patch: &serde_json::Value) {
    use serde_json::Value;
    match patch {
        Value::Object(patch_map) => {
            if !target.is_object() {
                *target = Value::Object(serde_json::Map::new());
            }
            let target_map = target.as_object_mut().expect("ensured object above");
            for (key, value) in patch_map {
                if value.is_null() {
                    target_map.remove(key);
                } else if let Some(existing) = target_map.get_mut(key) {
                    merge_json(existing, value);
                } else {
                    target_map.insert(key.clone(), value.clone());
                }
            }
        }
        _ => {
            *target = patch.clone();
        }
    }
}

pub(crate) fn scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    tx: Sender<ScanEvent>,
    cancel: ScanCancellation,
    input: serde_json::Value,
    registry: ModuleRegistry,
    config: V2Config,
    thinking_level: Option<String>,
) {
    if let Err(error) = run_scan_worker(
        target,
        db_path,
        &tx,
        &cancel,
        input,
        registry,
        config,
        thinking_level,
    ) {
        let _ = tx.send(ScanEvent::Failed {
            error: error.to_string(),
        });
    }
}

pub(crate) fn run_scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    input: serde_json::Value,
    registry: ModuleRegistry,
    config: V2Config,
    thinking_level: Option<String>,
) -> Result<()> {
    if cancel.is_cancelled() {
        anyhow::bail!("scan cancelled");
    }
    run_registry_scan_worker(
        target,
        db_path,
        tx,
        cancel,
        input,
        registry,
        config,
        thinking_level,
    )
}

pub(crate) fn run_registry_scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    input: serde_json::Value,
    registry: ModuleRegistry,
    config: V2Config,
    thinking_level: Option<String>,
) -> Result<()> {
    let workspace = prepare_scan_worker_workspace(target)?;
    let store = FindingStore::open(db_path)?;
    let runtime = if kuzushi_core::modules::wants_sast_runtime(&input) {
        Some(
            PiAgentCoreRuntime::from_config(
                &config,
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            )?
            .with_thinking_level(thinking_level),
        )
    } else {
        None
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
    };
    let _ = tx.send(ScanEvent::Stage("running sast:scan".to_string()));
    let result = registry.execute_tool_with_runtime(
        "sast:scan",
        input,
        &ctx,
        runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
    )?;
    if cancel.is_cancelled() {
        anyhow::bail!("scan cancelled");
    }
    send_registry_scan_finished(tx, result)
}

fn send_registry_scan_finished(tx: &Sender<ScanEvent>, result: serde_json::Value) -> Result<()> {
    let run_id = result
        .pointer("/data/runId")
        .and_then(serde_json::Value::as_str)
        .context("sast:scan result did not include data.runId")?;
    let findings_count = result
        .pointer("/data/findingsCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    let _ = tx.send(ScanEvent::Finished {
        run_id: run_id.to_string(),
        findings_count,
    });
    Ok(())
}
