use super::*;

#[derive(Debug)]
pub(crate) enum ScanEvent {
    Started {
        run_id: String,
        target: PathBuf,
    },
    Stage(String),
    FindingStored {
        fingerprint: String,
        severity: Severity,
        title: String,
    },
    Finished {
        run_id: String,
        findings_count: usize,
    },
    Failed {
        error: String,
    },
    Cancelled {
        run_id: String,
    },
}

#[derive(Debug)]
pub(crate) enum ToolEvent {
    Finished {
        tool_name: String,
        result: serde_json::Value,
    },
    Failed {
        tool_name: String,
        error: String,
    },
}

#[derive(Debug)]
pub(crate) enum AgentEvent {
    Answered { text: String },
    Failed { error: String },
}

#[derive(Debug)]
pub(crate) enum PlanEvent {
    Proposed(PlanProposal),
    Failed { error: String },
}

#[derive(Debug)]
pub(crate) enum ThreatPatchEvent {
    Proposed(ThreatPatch),
    Answer { text: String },
    Failed { error: String },
}

pub(crate) fn background_tool_worker(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: serde_json::Value,
    thinking_level: Option<String>,
    tx: Sender<ToolEvent>,
    trace_handle: Option<TraceHandle>,
) {
    let result = run_background_tool(
        registry,
        config,
        &workspace,
        &tool_name,
        input,
        thinking_level,
        trace_handle,
    );
    let event = match result {
        Ok(result) => ToolEvent::Finished { tool_name, result },
        Err(error) => ToolEvent::Failed {
            tool_name,
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}
