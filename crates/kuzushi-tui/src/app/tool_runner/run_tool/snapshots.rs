use super::*;

impl ShellApp {
    /// Cache structured snapshot of a tool result for the renderer to read
    /// instead of grepping the freeform `app.log` lines. Keeps recon /
    /// carlini-threat-hunt / agentic-sast snapshots reachable across log
    /// truncation.
    pub(crate) fn cache_tool_snapshot(&mut self, tool_name: &str, result: &serde_json::Value) {
        if tool_name.starts_with("pwn:") {
            self.cache_pwn_snapshot(tool_name, result);
            return;
        }
        let Some(data) = result.get("data") else {
            return;
        };
        if tool_name.starts_with("recon:") {
            let hosts = data
                .get("hosts")
                .and_then(|value| serde_json::from_value::<Vec<ReconHost>>(value.clone()).ok())
                .unwrap_or_default();
            let services = data
                .get("services")
                .and_then(|value| serde_json::from_value::<Vec<ReconService>>(value.clone()).ok())
                .unwrap_or_default();
            let notes = data
                .get("notes")
                .and_then(|value| serde_json::from_value::<Vec<ReconNote>>(value.clone()).ok())
                .unwrap_or_default();
            let last_tool = data
                .get("tool")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| tool_name.to_string());
            let last_target = data
                .get("target")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            self.recon_snapshot = Some(ReconSnapshot {
                hosts,
                services,
                notes,
                last_tool: Some(last_tool),
                last_target,
            });
        } else if tool_name.starts_with("carlini-threat-hunt:") {
            if let Ok(report) = serde_json::from_value::<CarliniThreatHuntReport>(data.clone()) {
                self.carlini_snapshot = Some(report);
            }
        } else if tool_name.starts_with("agentic-sast:") {
            if let Ok(report) = serde_json::from_value::<AgenticSastReport>(data.clone()) {
                self.agentic_sast_snapshot = Some(report);
            }
        } else if tool_name == "patch:run" || tool_name == "patch:finding" {
            // `patch:run` / `patch:finding` produce a staged patch the
            // operator must approve (`design/mockups/patch.jsx`).  Cache
            // the structured payload into `pending_patch` and navigate
            // to the Patch view so it surfaces immediately.
            if let Some(patch) = parse_pending_patch(data) {
                let alias = patch.alias.clone();
                self.pending_patch = Some(patch);
                self.shell_view = ShellView::Patch(alias);
            }
        }
    }
}
