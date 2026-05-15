use super::*;

impl ShellApp {
    /// Cache structured snapshot of a tool result for the renderer to read
    /// instead of grepping the freeform `app.log` lines. Keeps recon /
    /// offense-review / agentic-sast snapshots reachable across log truncation.
    pub(crate) fn cache_tool_snapshot(&mut self, tool_name: &str, result: &serde_json::Value) {
        if tool_name.starts_with("pwn:") {
            self.cache_pwn_snapshot(tool_name, result);
            return;
        }
        let Some(data) = result.get("data") else {
            return;
        };
        for cache in SNAPSHOT_CACHES {
            if cache(self, tool_name, data) {
                return;
            }
        }
    }
}

type SnapshotCache = fn(&mut ShellApp, &str, &serde_json::Value) -> bool;

const SNAPSHOT_CACHES: &[SnapshotCache] = &[
    cache_recon_snapshot,
    cache_threat_hunt_snapshot,
    cache_agentic_sast_snapshot,
    cache_patch_snapshot,
];

fn cache_recon_snapshot(app: &mut ShellApp, tool_name: &str, data: &serde_json::Value) -> bool {
    if !tool_name.starts_with("recon:") {
        return false;
    }
    app.recon_snapshot = Some(ReconSnapshot {
        hosts: recon_hosts(data),
        services: recon_services(data),
        notes: recon_notes(data),
        last_tool: Some(data_string(data, "tool").unwrap_or_else(|| tool_name.to_string())),
        last_target: data_string(data, "target"),
    });
    true
}

fn cache_threat_hunt_snapshot(
    app: &mut ShellApp,
    tool_name: &str,
    data: &serde_json::Value,
) -> bool {
    if !is_threat_hunt_snapshot_tool(tool_name) {
        return false;
    }
    if let Ok(report) = serde_json::from_value::<CarliniThreatHuntReport>(data.clone()) {
        app.carlini_snapshot = Some(report);
    }
    true
}

fn cache_agentic_sast_snapshot(
    app: &mut ShellApp,
    tool_name: &str,
    data: &serde_json::Value,
) -> bool {
    if !tool_name.starts_with("agentic-sast:") {
        return false;
    }
    if let Ok(report) = serde_json::from_value::<AgenticSastReport>(data.clone()) {
        app.agentic_sast_snapshot = Some(report);
    }
    true
}

fn cache_patch_snapshot(app: &mut ShellApp, tool_name: &str, data: &serde_json::Value) -> bool {
    if tool_name != "patch:run" && tool_name != "patch:finding" {
        return false;
    }
    if let Some(patch) = parse_pending_patch(data) {
        let alias = patch.alias.clone();
        app.pending_patch = Some(patch);
        app.shell_view = ShellView::Patch(alias);
    }
    true
}

fn is_threat_hunt_snapshot_tool(tool_name: &str) -> bool {
    tool_name.starts_with("carlini-threat-hunt:") || tool_name == "offense-review:threat-hunt"
}

fn recon_hosts(data: &serde_json::Value) -> Vec<ReconHost> {
    data.get("hosts")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn recon_services(data: &serde_json::Value) -> Vec<ReconService> {
    data.get("services")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn recon_notes(data: &serde_json::Value) -> Vec<ReconNote> {
    data.get("notes")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn data_string(data: &serde_json::Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}
