use super::*;

pub(crate) fn parse_threat_patch_json(goal: &str, body: &str) -> Result<ThreatPatch> {
    let parsed = parse_threat_patch_value(body)?;
    let patch = threat_patch_object(&parsed)?;
    Ok(ThreatPatch {
        goal: goal.to_string(),
        summary: threat_patch_summary(goal, &parsed),
        patch,
        unsupported: threat_patch_unsupported(&parsed),
    })
}

fn parse_threat_patch_value(body: &str) -> Result<serde_json::Value> {
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
    serde_json::from_str(json_slice).context("threat-patch JSON did not parse")
}

fn threat_patch_summary(goal: &str, parsed: &serde_json::Value) -> String {
    parsed
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(goal)
        .to_string()
}

fn threat_patch_object(parsed: &serde_json::Value) -> Result<serde_json::Value> {
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
    Ok(patch)
}

fn threat_patch_unsupported(parsed: &serde_json::Value) -> Vec<String> {
    parsed
        .get("unsupported")
        .and_then(serde_json::Value::as_array)
        .map(|items| unsupported_items(items))
        .unwrap_or_default()
}

fn unsupported_items(items: &[serde_json::Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect()
}

pub(crate) fn merge_json(target: &mut serde_json::Value, patch: &serde_json::Value) {
    use serde_json::Value;
    match patch {
        Value::Object(patch_map) => {
            merge_json_object(target, patch_map);
        }
        _ => {
            *target = patch.clone();
        }
    }
}

fn merge_json_object(
    target: &mut serde_json::Value,
    patch_map: &serde_json::Map<String, serde_json::Value>,
) {
    use serde_json::Value;
    if !target.is_object() {
        *target = Value::Object(serde_json::Map::new());
    }
    let target_map = target.as_object_mut().expect("ensured object above");
    for (key, value) in patch_map {
        merge_json_field(target_map, key, value);
    }
}

fn merge_json_field(
    target_map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &serde_json::Value,
) {
    if value.is_null() {
        target_map.remove(key);
    } else if let Some(existing) = target_map.get_mut(key) {
        merge_json(existing, value);
    } else {
        target_map.insert(key.to_string(), value.clone());
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
    trace_handle: TraceHandle,
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
        trace_handle,
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
    trace_handle: TraceHandle,
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
        trace_handle,
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
    trace_handle: TraceHandle,
) -> Result<()> {
    let invocation = prepare_registry_scan_invocation(
        target,
        db_path,
        input,
        config,
        thinking_level,
        cancel,
        trace_handle,
    )?;
    let _ = tx.send(ScanEvent::Stage("running sast:scan".to_string()));
    let result = invocation.execute(registry)?;
    send_registry_scan_result(cancel, tx, result)
}

struct RegistryScanInvocation {
    workspace: WorkspaceTarget,
    store: FindingStore,
    input: serde_json::Value,
    config: V2Config,
    runtime: Option<LangGraphRuntime>,
    trace_handle: TraceHandle,
}

impl RegistryScanInvocation {
    fn execute(self, registry: ModuleRegistry) -> Result<serde_json::Value> {
        let RegistryScanInvocation {
            workspace,
            store,
            input,
            config,
            runtime,
            trace_handle,
        } = self;
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace_handle),
        };
        registry.execute_tool_with_runtime(
            "sast:scan",
            input,
            &ctx,
            runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
        )
    }
}

fn prepare_registry_scan_invocation(
    target: PathBuf,
    db_path: PathBuf,
    input: serde_json::Value,
    config: V2Config,
    thinking_level: Option<String>,
    cancel: &ScanCancellation,
    trace_handle: TraceHandle,
) -> Result<RegistryScanInvocation> {
    let (workspace, store) = registry_scan_workspace_store(target, db_path)?;
    let runtime = registry_scan_runtime(&input, &config, thinking_level, cancel)?;
    Ok(RegistryScanInvocation {
        workspace,
        store,
        input,
        config,
        runtime,
        trace_handle,
    })
}

fn registry_scan_workspace_store(
    target: PathBuf,
    db_path: PathBuf,
) -> Result<(WorkspaceTarget, FindingStore)> {
    Ok((
        prepare_scan_worker_workspace(target)?,
        FindingStore::open(db_path)?,
    ))
}

fn prepare_scan_worker_workspace(target: PathBuf) -> Result<WorkspaceTarget> {
    let workspace = WorkspaceTarget::new(&target)?;
    workspace.ensure_state_dir()?;
    Ok(workspace)
}

fn send_registry_scan_result(
    cancel: &ScanCancellation,
    tx: &Sender<ScanEvent>,
    result: serde_json::Value,
) -> Result<()> {
    ensure_scan_not_cancelled(cancel)?;
    send_registry_scan_finished(tx, result)
}

fn registry_scan_runtime(
    input: &serde_json::Value,
    config: &V2Config,
    thinking_level: Option<String>,
    cancel: &ScanCancellation,
) -> Result<Option<LangGraphRuntime>> {
    if !kuzushi_core::modules::wants_sast_runtime(input) {
        return Ok(None);
    }
    Ok(Some(
        LangGraphRuntime::from_config(config, scan_worker_runtime_cwd())?
            .with_thinking_level(thinking_level)
            .with_cancellation(cancel.clone()),
    ))
}

fn scan_worker_runtime_cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn ensure_scan_not_cancelled(cancel: &ScanCancellation) -> Result<()> {
    if cancel.is_cancelled() {
        anyhow::bail!("scan cancelled");
    }
    Ok(())
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
