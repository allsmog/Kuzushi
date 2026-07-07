use super::*;

impl ShellApp {
    /// Cache structured snapshot of a tool result for the renderer to read
    /// instead of grepping the freeform `app.log` lines. Keeps recon /
    /// offense-review / agentic-sast snapshots reachable across log truncation.
    pub(crate) fn cache_tool_snapshot(
        &mut self,
        tool_name: &str,
        result: &serde_json::Value,
    ) -> Vec<ShellEffect> {
        if tool_name.starts_with("pwn:") {
            return self.cache_pwn_snapshot(tool_name, result.get("data").unwrap_or(result));
        }
        let Some(data) = result.get("data") else {
            return Vec::new();
        };
        for cache in SNAPSHOT_CACHES {
            if cache(self, tool_name, data) {
                return Vec::new();
            }
        }
        Vec::new()
    }

    /// Reload the per-repo taint-flow + exploit-chain viz snapshots a previous
    /// session wrote, so the `/scene` attack-path and exploit-chain pages — and
    /// the Activity OUTPUT pinned views — are populated on launch. Findings (the
    /// heatmap + 3D surface) and the threat model (the DFD) already hydrate from
    /// their own stores. Best-effort: a missing/unreadable file leaves the page
    /// empty, exactly as a never-run tool would.
    pub(crate) fn hydrate_persisted_scene_snapshots(&mut self, root: Option<&std::path::Path>) {
        let Some(root) = root else {
            return;
        };
        self.hydrate_persisted_taint_flow(root);
        self.hydrate_persisted_exploit_chains(root);
    }

    fn hydrate_persisted_taint_flow(&mut self, root: &std::path::Path) {
        if let Some(flow) = kuzushi_core::capabilities::load_persistent_taint_flow(root)
            .as_ref()
            .and_then(taint_flow_from_data)
        {
            self.domain_mut().set_taint_flow(Some(flow));
        }
    }

    fn hydrate_persisted_exploit_chains(&mut self, root: &std::path::Path) {
        let Some(chain_data) = kuzushi_core::capabilities::load_persistent_exploit_chains(root)
        else {
            return;
        };
        let details = exploit_chain_details(&chain_data);
        if !details.is_empty() {
            self.domain_mut().set_exploit_chains(details);
            self.set_chain_aliases(exploit_chain_aliases(&chain_data));
        }
    }
}

type SnapshotCache = fn(&mut ShellApp, &str, &serde_json::Value) -> bool;

const SNAPSHOT_CACHES: &[SnapshotCache] = &[
    cache_recon_snapshot,
    cache_exploit_chain_snapshot,
    cache_taint_flow_snapshot,
    cache_threat_hunt_snapshot,
    cache_agentic_sast_snapshot,
    cache_patch_snapshot,
];

const MAX_EXPLOIT_CHAIN_SNAPSHOTS: usize = 25;
const MAX_EXPLOIT_CHAIN_STEPS: usize = 20;
const MAX_EXPLOIT_CHAIN_PRECONDITIONS: usize = 10;
const MAX_TAINT_FLOW_STAGES: usize = 25;
const MAX_RECON_HOSTS: usize = 200;
const MAX_RECON_SERVICES: usize = 500;
const MAX_RECON_NOTES: usize = 200;

fn cache_recon_snapshot(app: &mut ShellApp, tool_name: &str, data: &serde_json::Value) -> bool {
    if !tool_name.starts_with("recon:") {
        return false;
    }
    app.domain_mut().set_recon_snapshot(ReconSnapshot {
        hosts: recon_hosts(data),
        services: recon_services(data),
        notes: recon_notes(data),
        last_tool: Some(data_string(data, "tool").unwrap_or_else(|| tool_name.to_string())),
        last_target: data_string(data, "target"),
    });
    true
}

fn cache_exploit_chain_snapshot(
    app: &mut ShellApp,
    tool_name: &str,
    data: &serde_json::Value,
) -> bool {
    if tool_name != "exploit-chain:scan" {
        return false;
    }
    app.set_chain_aliases(exploit_chain_aliases(data));
    app.domain_mut()
        .set_exploit_chains(exploit_chain_details(data));
    true
}

/// Detailed chains (with ordered steps) for the attack-tree visualization,
/// parallel to the minimal `chains` aliases.
fn exploit_chain_details(data: &serde_json::Value) -> Vec<ExploitChainDetail> {
    data.get("chains")
        .and_then(serde_json::Value::as_array)
        .map(|chains| {
            chains
                .iter()
                .take(MAX_EXPLOIT_CHAIN_SNAPSHOTS)
                .filter_map(exploit_chain_detail)
                .collect()
        })
        .unwrap_or_default()
}

fn exploit_chain_detail(chain: &serde_json::Value) -> Option<ExploitChainDetail> {
    Some(ExploitChainDetail {
        id: data_string(chain, "id")?,
        title: data_string(chain, "name")?,
        severity: chain_severity(
            chain
                .get("overallSeverity")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("high"),
        ),
        narrative: data_string(chain, "narrative"),
        impact_description: data_string(chain, "impactDescription"),
        preconditions: limited_string_array(
            chain,
            "preconditions",
            MAX_EXPLOIT_CHAIN_PRECONDITIONS,
        ),
        steps: chain
            .get("steps")
            .and_then(serde_json::Value::as_array)
            .map(|steps| {
                steps
                    .iter()
                    .take(MAX_EXPLOIT_CHAIN_STEPS)
                    .filter_map(exploit_chain_step)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

fn exploit_chain_step(step: &serde_json::Value) -> Option<ExploitChainStep> {
    Some(ExploitChainStep {
        role: data_string(step, "role").unwrap_or_default(),
        description: data_string(step, "description").unwrap_or_default(),
        file: data_string(step, "filePath").unwrap_or_default(),
        line: step
            .get("startLine")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32,
    })
}

/// Cache the headline source→sink taint flow from `taint-iris:hunt` structured
/// output (`data.flows[]`) for the attack-path visualization. Only `taint-iris`
/// emits `flows[]`; `taint-iris-next` flattens its taint path into finding text.
fn cache_taint_flow_snapshot(
    app: &mut ShellApp,
    tool_name: &str,
    data: &serde_json::Value,
) -> bool {
    if tool_name != "taint-iris:hunt" {
        return false;
    }
    if let Some(flow) = taint_flow_from_data(data) {
        app.domain_mut().set_taint_flow(Some(flow));
    }
    true
}

fn taint_flow_from_data(data: &serde_json::Value) -> Option<TaintFlowSnapshot> {
    let flow = data
        .get("flows")
        .and_then(serde_json::Value::as_array)?
        .first()?;
    Some(TaintFlowSnapshot {
        cwe: data_string(flow, "cwe").unwrap_or_else(|| "CWE".to_string()),
        severity: data_string(flow, "severity").unwrap_or_else(|| "medium".to_string()),
        stages: flow
            .get("stages")
            .and_then(serde_json::Value::as_array)
            .map(|stages| {
                stages
                    .iter()
                    .take(MAX_TAINT_FLOW_STAGES)
                    .filter_map(taint_stage)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

fn taint_stage(stage: &serde_json::Value) -> Option<TaintStage> {
    Some(TaintStage {
        message: data_string(stage, "message").unwrap_or_default(),
        file: data_string(stage, "filePath")
            .or_else(|| data_string(stage, "file"))
            .unwrap_or_default(),
        line: stage
            .get("line")
            .or_else(|| stage.get("startLine"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32,
        snippet: data_string(stage, "snippet"),
    })
}

fn limited_string_array(value: &serde_json::Value, key: &str, limit: usize) -> Vec<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(limit)
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn exploit_chain_aliases(data: &serde_json::Value) -> Vec<ExploitChain> {
    data.get("chains")
        .and_then(serde_json::Value::as_array)
        .map(|chains| {
            chains
                .iter()
                .take(MAX_EXPLOIT_CHAIN_SNAPSHOTS)
                .filter_map(exploit_chain_alias)
                .collect()
        })
        .unwrap_or_default()
}

fn exploit_chain_alias(chain: &serde_json::Value) -> Option<ExploitChain> {
    Some(ExploitChain {
        id: data_string(chain, "id")?,
        severity: chain_severity(chain.get("overallSeverity")?.as_str()?),
        title: data_string(chain, "name")?,
    })
}

fn chain_severity(value: &str) -> ChainSeverity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" => ChainSeverity::Critical,
        "medium" | "med" => ChainSeverity::Medium,
        _ => ChainSeverity::High,
    }
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
        app.domain_mut().set_carlini_snapshot(report);
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
        app.domain_mut().set_agentic_sast_snapshot(report);
    }
    true
}

fn cache_patch_snapshot(app: &mut ShellApp, tool_name: &str, data: &serde_json::Value) -> bool {
    if tool_name != "patch:run" && tool_name != "patch:finding" {
        return false;
    }
    if let Some(patch) = parse_pending_patch(data) {
        let alias = patch.alias.clone();
        app.engagement.set_pending_patch(patch);
        app.router.patch_mut().open(alias);
        app.set_shell_view(ShellView::Patch);
    }
    true
}

fn is_threat_hunt_snapshot_tool(tool_name: &str) -> bool {
    tool_name.starts_with("carlini-threat-hunt:") || tool_name == "offense-review:threat-hunt"
}

fn recon_hosts(data: &serde_json::Value) -> Vec<ReconHost> {
    let hosts = data
        .get("hosts")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default();
    capped_vec(hosts, MAX_RECON_HOSTS)
}

fn recon_services(data: &serde_json::Value) -> Vec<ReconService> {
    let services = data
        .get("services")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default();
    capped_vec(services, MAX_RECON_SERVICES)
}

fn recon_notes(data: &serde_json::Value) -> Vec<ReconNote> {
    let notes = data
        .get("notes")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default();
    capped_vec(notes, MAX_RECON_NOTES)
}

fn data_string(data: &serde_json::Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}

fn capped_vec<T>(mut values: Vec<T>, limit: usize) -> Vec<T> {
    values.truncate(limit);
    values
}

#[cfg(test)]
mod tests;
