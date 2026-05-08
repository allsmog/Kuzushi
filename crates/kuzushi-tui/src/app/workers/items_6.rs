use super::prelude::*;
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
    options: ScanRunOptions,
) {
    if let Err(error) = run_scan_worker(target, db_path, &tx, &cancel, &options) {
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
    options: &ScanRunOptions,
) -> Result<()> {
    let session = start_scan_worker_session(target, db_path, tx)?;
    run_scan_worker_session(session, tx, cancel, options)
}

pub(crate) fn run_scan_worker_session(
    session: ScanWorkerSession,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    options: &ScanRunOptions,
) -> Result<()> {
    let scanners = scan_worker_engines(options)?;
    run_scan_worker_scanners(session, tx, cancel, options, scanners)
}
