use std::sync::mpsc;
use std::thread;

use kuzushi_core::{
    append_run_trace_step, new_run_id, write_run_artifact_json, write_run_summary,
    AgenticSastReport, CarliniThreatHuntReport, ReconHost, ReconNote, ReconService, RunSummary,
    RunTraceStep, WorkspaceTarget,
};

use super::approval::{confirm_gate_for_tool, parse_pending_patch};
use super::options::closest_option_names;
use super::prereq_chain::{prereq_steps_for, PendingPrereqPrompt, PrereqChain, PrereqStep};
use super::workers::{background_tool_worker, tool_run_status};
use super::{
    thinking_level_from_input, with_next_step, ReconSnapshot, ShellApp, ShellView, ToolEvent,
};

impl ShellApp {
    pub(super) fn run_tool(&mut self, tool: Option<String>, input: Option<String>) {
        if let Some(tool_name) = self.tool_running.as_deref() {
            self.log(
                "tool",
                format!("{tool_name} is still running; wait for its result before starting another tool"),
            );
            return;
        }

        let tool_name = match tool {
            Some(tool) => tool,
            None => match self.default_tool_for_run_command() {
                Some(tool) => tool,
                None => {
                    self.log(
                        "error",
                        "run needs a tool, focused module, or loaded sast:scan. Next: modules or run <tool>",
                    );
                    return;
                }
            },
        };
        let tool_name = self.resolve_focused_tool_name(tool_name);

        let input = match input {
            Some(raw) if !raw.trim().is_empty() => match serde_json::from_str(&raw) {
                Ok(input) => input,
                Err(error) => {
                    self.log(
                        "error",
                        format!("run input must be JSON: {error}. Next: run <tool> {{}}"),
                    );
                    return;
                }
            },
            _ => serde_json::json!({}),
        };
        let input =
            match self
                .registry
                .prepare_tool_input(&tool_name, input, Some(&self.option_store))
            {
                Ok(input) => input,
                Err(error) => {
                    self.log(
                        "error",
                        with_next_step(
                            error.to_string(),
                            "tools, options <tool>, or run <tool> {}",
                        ),
                    );
                    return;
                }
            };

        // Confirm gate preflight (`design/mockups/confirm-dialog.jsx`).
        // If the tool + input matches a known-risky shape (network
        // egress, fs:write outside `.kuzushi/`, destructive verb),
        // surface a `PendingConfirm` and pause the dispatch.  The
        // operator resolves with y/Y/n/N; on `y`/`Y` they re-run the
        // command and the gate doesn't fire again because `remembered`
        // adds the target to the session allowlist.
        if let Some(request) = confirm_gate_for_tool(&tool_name, &input, &self.confirm_allowlist) {
            self.log(
                "system",
                format!(
                    "{} requires approval — {}",
                    tool_name,
                    request.kind.label().to_lowercase()
                ),
            );
            self.request_confirm(request);
            return;
        }

        let workspace = match self.current_workspace() {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(
                        error.to_string(),
                        "scan <target> or start kuzushi shell --target .",
                    ),
                );
                return;
            }
        };
        let tool_thinking_level =
            thinking_level_from_input(&input).or_else(|| self.session_thinking_level.clone());
        let workspace = workspace.expect("current_workspace returned Some workspace");

        // Build the static prerequisite chain for this tool (e.g. carlini
        // requires context:build then threat-model:build).  When non-empty
        // we route the dispatch through `start_prereq_chain` so missing
        // artifacts auto-run and existing artifacts trigger a reuse-or-
        // regenerate prompt before continuing.
        let target_root = workspace.root().to_path_buf();
        let prereqs = prereq_steps_for(&tool_name, &target_root);
        if !prereqs.is_empty() {
            self.shell_view = ShellView::ModuleRun;
            self.start_prereq_chain(
                prereqs,
                tool_name,
                input,
                workspace,
                tool_thinking_level,
            );
            return;
        }

        let status = tool_run_status(&tool_name);
        self.shell_view = ShellView::ModuleRun;
        self.start_background_tool(
            tool_name,
            input,
            workspace,
            status,
            tool_thinking_level,
        );
    }

    /// Begin a prerequisite chain.  We walk the steps in order.  For each
    /// step:
    ///   - If the artifact already exists, pause for an operator
    ///     reuse-or-regenerate decision.
    ///   - Else dispatch the step's tool through
    ///     `start_background_tool`, then advance once it finishes (handled
    ///     in `apply_tool_event`).
    pub(super) fn start_prereq_chain(
        &mut self,
        steps: Vec<PrereqStep>,
        final_tool: String,
        final_input: serde_json::Value,
        workspace: WorkspaceTarget,
        thinking_level: Option<String>,
    ) {
        let chain = PrereqChain::new(steps, final_tool, final_input, thinking_level);
        self.log(
            "system",
            format!(
                "{}: resolving prerequisites — {}",
                chain.final_tool,
                chain
                    .remaining
                    .iter()
                    .map(|s| s.tool.as_str())
                    .collect::<Vec<_>>()
                    .join(" → ")
            ),
        );
        self.pending_chain = Some(chain);
        self.advance_chain(workspace);
    }

    /// Advance the chain after a step finishes (or after a reuse decision).
    /// Walks remaining steps, pausing on the first existing artifact for
    /// operator input.  When the queue is empty, dispatches the final tool.
    pub(super) fn advance_chain(&mut self, workspace: WorkspaceTarget) {
        loop {
            // Snapshot decision-relevant state out of `self.pending_chain`
            // so we can mutate `self` (logging, dispatch) without holding
            // an outstanding borrow.
            let Some(chain) = self.pending_chain.as_ref() else {
                return;
            };
            let final_tool = chain.final_tool.clone();
            let final_input = chain.final_input.clone();
            let final_thinking = chain.final_thinking_level.clone();
            let finals_dispatched = chain.finals_dispatched;
            let next_step = chain.next_step().cloned();

            let Some(step) = next_step else {
                if finals_dispatched {
                    // Final tool already dispatched; nothing to advance.
                    return;
                }
                // Mark finals_dispatched before dispatching so the
                // post-dispatch event handler recognises completion via
                // `was_final_dispatch`.
                if let Some(chain) = self.pending_chain.as_mut() {
                    chain.finals_dispatched = true;
                }
                let status = tool_run_status(&final_tool);
                self.start_background_tool(
                    final_tool,
                    final_input,
                    workspace,
                    status,
                    final_thinking,
                );
                return;
            };

            if step.artifact_path.exists() {
                self.pending_prereq_prompt = Some(PendingPrereqPrompt {
                    current_tool: step.tool.clone(),
                    current_artifact_path: step.artifact_path.clone(),
                    current_artifact_label: step.artifact_label.clone(),
                    final_tool: final_tool.clone(),
                });
                self.log(
                    "system",
                    format!(
                        "existing {} at {} — reuse [r] or regenerate [g]?",
                        step.artifact_label,
                        step.artifact_path.display()
                    ),
                );
                return;
            }

            // Artifact missing — dispatch the prereq tool and stop the
            // loop; we'll resume in `apply_tool_event` once it finishes.
            if let Some(chain) = self.pending_chain.as_mut() {
                chain.running_step = Some(step.tool.clone());
            }
            let dispatched_tool = step.tool.clone();
            self.log(
                "system",
                format!(
                    "{dispatched_tool} required by {final_tool} — running automatically"
                ),
            );
            let status = tool_run_status(&dispatched_tool);
            self.start_background_tool(
                dispatched_tool,
                serde_json::json!({}),
                workspace,
                status,
                final_thinking,
            );
            return;
        }
    }

    /// Operator answered the reuse/regenerate prompt.
    /// `reuse=true` → skip the current step (the artifact stays as-is).
    /// `reuse=false` → run the step's tool to regenerate the artifact.
    pub fn resolve_prereq_prompt(&mut self, reuse: bool) {
        let Some(prompt) = self.pending_prereq_prompt.take() else {
            return;
        };
        let dropped = match self.pending_chain.as_mut() {
            Some(chain) => chain.drop_first(),
            None => None,
        };
        let Some(step) = dropped else {
            return;
        };
        debug_assert_eq!(step.tool, prompt.current_tool);
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                self.pending_chain = None;
                return;
            }
        };
        if reuse {
            self.log(
                "system",
                format!(
                    "✓ reusing existing {} at {}",
                    step.artifact_label,
                    step.artifact_path.display()
                ),
            );
            self.advance_chain(workspace);
        } else {
            self.log(
                "system",
                format!(
                    "↻ regenerating {} via {}",
                    step.artifact_label, step.tool
                ),
            );
            // Delete the cached artifact and re-queue the step so
            // advance_chain falls through to the dispatch branch.
            let _ = std::fs::remove_file(&step.artifact_path);
            if let Some(chain) = self.pending_chain.as_mut() {
                chain.remaining.insert(0, step);
            }
            self.advance_chain(workspace);
        }
    }

    pub(super) fn start_background_tool(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
    ) {
        if let Some(active) = self.tool_running.as_deref() {
            self.log(
                "tool",
                format!(
                    "{active} is still running; wait for its result before starting {tool_name}"
                ),
            );
            return;
        }

        let registry = self.registry.clone();
        let config = self.config.clone();
        let target = workspace.root().to_path_buf();
        let run_id = new_run_id("tool");
        let target_label = target.display().to_string();
        let summary = RunSummary::running(
            run_id.clone(),
            "tool",
            Some(tool_name.clone()),
            target_label.clone(),
        );
        let _ = write_run_summary(&target, &summary);
        let _ = append_run_trace_step(
            &target,
            &run_id,
            &RunTraceStep::new(1, "tool", format!("{tool_name} started")),
        );
        let (tx, rx) = mpsc::channel();
        self.target = Some(target.clone());
        self.tool_rx = Some(rx);
        self.tool_running = Some(tool_name.clone());
        self.tool_run_id = Some(run_id.clone());
        self.tool_abort_requested = false;
        self.log(
            "tool",
            format!(
                "running {tool_name} in background; {status} under {target_label} · run {run_id}"
            ),
        );

        thread::spawn(move || {
            background_tool_worker(
                registry,
                config,
                workspace,
                tool_name,
                input,
                thinking_level,
                tx,
            )
        });
    }

    pub(super) fn apply_tool_event(&mut self, event: ToolEvent) {
        let abort_requested = self.tool_abort_requested;
        let run_id = self.tool_run_id.take();
        let target = self.target.clone();
        self.tool_running = None;
        self.tool_abort_requested = false;
        match event {
            ToolEvent::Finished { tool_name, result } => {
                record_tool_run_complete(target.as_deref(), run_id.as_deref(), &tool_name, &result);
                if abort_requested {
                    self.log(
                        "tool",
                        format!(
                            "{tool_name} completed after abort request; applying completed result"
                        ),
                    );
                }
                self.apply_tool_result(&tool_name, result);
                self.advance_chain_after_step(&tool_name);
            }
            ToolEvent::Failed { tool_name, error } => {
                record_tool_run_failed(target.as_deref(), run_id.as_deref(), &tool_name, &error);
                let message = with_next_step(error, "tools, options <tool>, or model <n>");
                if abort_requested {
                    self.log(
                        "error",
                        format!("{tool_name} ended after abort request: {message}"),
                    );
                } else {
                    self.log("error", message);
                }
                // Abort the chain on prereq failure — the operator must
                // see the underlying error and choose how to proceed.
                if let Some(chain) = self.pending_chain.take() {
                    self.log(
                        "system",
                        format!(
                            "{} prerequisite chain aborted after {tool_name} failed",
                            chain.final_tool
                        ),
                    );
                }
                self.pending_prereq_prompt = None;
            }
        }
    }

    /// If `tool_name` was the current chain step, drop it from the queue
    /// and advance.  No-op when no chain is active or the finished tool
    /// is unrelated to the chain.
    fn advance_chain_after_step(&mut self, tool_name: &str) {
        let Some(chain) = self.pending_chain.as_mut() else {
            return;
        };
        let was_chain_step = chain.running_step.as_deref() == Some(tool_name);
        let was_final_dispatch = chain.finals_dispatched && chain.final_tool == tool_name;
        if was_chain_step {
            let _ = chain.drop_first();
            chain.running_step = None;
        } else if was_final_dispatch {
            self.pending_chain = None;
            return;
        } else {
            return;
        }
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                self.pending_chain = None;
                return;
            }
        };
        self.advance_chain(workspace);
    }

    pub(super) fn apply_tool_result(&mut self, tool_name: &str, result: serde_json::Value) {
        if let Some(cost_usd) = extract_cost_usd(&result) {
            self.record_cost(cost_usd);
        }
        if matches!(tool_name, "context:build" | "context-lite:index") {
            let _ = self.refresh_context_view();
        }
        self.cache_tool_snapshot(tool_name, &result);
        let rendered = result
            .get("output")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
            });
        self.log("result", rendered);
    }

    /// Cache structured snapshot of a tool result for the renderer to read
    /// instead of grepping the freeform `app.log` lines. Keeps recon /
    /// carlini-threat-hunt / agentic-sast snapshots reachable across log
    /// truncation.
    pub(crate) fn cache_tool_snapshot(&mut self, tool_name: &str, result: &serde_json::Value) {
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

    pub(super) fn unknown_module_message(&self, module: &str) -> String {
        let module_ids = self
            .registry
            .modules()
            .map(|entry| entry.metadata().id.clone())
            .collect::<Vec<_>>();
        let module_refs = module_ids.iter().map(String::as_str).collect::<Vec<_>>();
        let closest = closest_option_names(module, &module_refs);
        let closest = if closest.is_empty() {
            "none".to_string()
        } else {
            closest.join(", ")
        };
        format!("unknown module {module:?}. Closest: {closest}. Next: modules or use <module-id>")
    }

    pub(super) fn default_tool_for_focused_module(&self) -> Option<String> {
        let module = self.focused_module.as_ref()?;
        if module == "verify" && self.registry.resolve_tool("verify:finding").is_some() {
            return Some("verify:finding".to_string());
        }
        let prefix = format!("{module}:");
        self.registry
            .tools()
            .find(|tool| tool.name.starts_with(&prefix))
            .map(|tool| tool.name.clone())
    }

    pub(super) fn default_tool_for_run_command(&self) -> Option<String> {
        self.default_tool_for_focused_module().or_else(|| {
            self.registry
                .resolve_tool("sast:scan")
                .map(|_| "sast:scan".to_string())
        })
    }

    pub(super) fn resolve_focused_tool_name(&self, tool_name: String) -> String {
        if tool_name.contains(':') {
            return tool_name;
        }
        let Some(module) = self.focused_module.as_ref() else {
            return tool_name;
        };
        let candidate = format!("{module}:{tool_name}");
        if self.registry.resolve_tool(&candidate).is_some() {
            candidate
        } else {
            tool_name
        }
    }
}

fn extract_cost_usd(result: &serde_json::Value) -> Option<f64> {
    result
        .get("costUsd")
        .and_then(serde_json::Value::as_f64)
        .or_else(|| {
            result
                .pointer("/data/costUsd")
                .and_then(serde_json::Value::as_f64)
        })
        .filter(|cost| cost.is_finite() && *cost >= 0.0)
}

fn record_tool_run_complete(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    result: &serde_json::Value,
) {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return;
    };
    let artifact = write_run_artifact_json(target, run_id, "result.json", "result", result).ok();
    let mut summary = RunSummary::running(
        run_id.to_string(),
        "tool",
        Some(tool_name.to_string()),
        target.display().to_string(),
    )
    .complete()
    .with_findings(extract_findings_count(result))
    .with_cost(extract_cost_usd(result));
    if let Some(artifact) = artifact {
        summary = summary.with_artifact(artifact);
    }
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(2, "tool", format!("{tool_name} complete"))
            .with_cost_usd(extract_cost_usd(result)),
    );
    let _ = write_run_summary(target, &summary);
}

fn record_tool_run_failed(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    error: &str,
) {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return;
    };
    let summary = RunSummary::running(
        run_id.to_string(),
        "tool",
        Some(tool_name.to_string()),
        target.display().to_string(),
    )
    .failed(error.to_string());
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(2, "tool", format!("{tool_name} failed")),
    );
    let _ = write_run_summary(target, &summary);
}

fn extract_findings_count(value: &serde_json::Value) -> Option<u64> {
    value
        .pointer("/data/findingsCount")
        .or_else(|| value.get("findingsCount"))
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            value
                .pointer("/data/findings")
                .and_then(serde_json::Value::as_array)
                .map(|findings| findings.len() as u64)
        })
}
