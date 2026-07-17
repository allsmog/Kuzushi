use super::fanout::{
    CompletedWorkItem, FailedWorkItem, FanoutOutcome, PartialFailurePolicy, WorkItem, WorkItemKey,
};
use super::manifest::RunbookManifest;
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::path::Path;

use crate::run_artifacts::{
    read_run_artifact_text, write_run_artifact_json, ParentScope, RunArtifact, RunArtifactRead,
    TraceHandle,
};

pub struct RunbookRuntime<'a> {
    target: &'a Path,
    run_id: &'a str,
    manifest: &'static RunbookManifest,
    trace: Option<&'a TraceHandle>,
}

impl<'a> RunbookRuntime<'a> {
    pub fn new(
        target: &'a Path,
        run_id: &'a str,
        manifest: &'static RunbookManifest,
        trace: Option<&'a TraceHandle>,
    ) -> Self {
        Self {
            target,
            run_id,
            manifest,
            trace,
        }
    }

    pub fn manifest(&self) -> &'static RunbookManifest {
        self.manifest
    }

    /// Emit a manifest-checked step. Runbooks are implemented as Rust code;
    /// the manifest provides stable labels for Activity and snapshot tests.
    pub fn enter_step(&self, step_id: &str) -> Result<Option<usize>> {
        self.manifest.assert_step(step_id)?;
        let Some(trace) = self.trace else {
            return Ok(None);
        };
        let label = self.manifest.step_label(step_id).unwrap_or(step_id);
        Ok(Some(
            trace
                .step("reasoning", self.manifest.owner_tool, label)
                .emit(),
        ))
    }

    pub fn parent_scope(&self, parent: Option<usize>) -> Option<ParentScope> {
        match (self.trace, parent) {
            (Some(trace), Some(parent)) => Some(trace.parent_scope(parent)),
            _ => None,
        }
    }

    pub fn write_checkpoint(
        &self,
        step_id: &str,
        label: impl Into<String>,
        value: &Value,
    ) -> Result<RunArtifact> {
        self.manifest.assert_step(step_id)?;
        let leaf = format!(
            "runbooks/{}/checkpoints/{}.json",
            self.manifest.id,
            sanitize_leaf(step_id)
        );
        let value = with_runbook_metadata(value.clone(), self.manifest, self.run_id);
        write_run_artifact_json(self.target, self.run_id, &leaf, label, &value)
    }

    pub fn write_artifact(
        &self,
        leaf: &str,
        label: impl Into<String>,
        value: &Value,
    ) -> Result<RunArtifact> {
        let leaf = format!(
            "runbooks/{}/{}",
            self.manifest.id,
            leaf.trim_start_matches('/')
        );
        let value = with_runbook_metadata(value.clone(), self.manifest, self.run_id);
        write_run_artifact_json(self.target, self.run_id, &leaf, label, &value)
    }

    /// Work-item fanout with item-level checkpoints. This synchronous
    /// implementation is the first hardened primitive; callers can layer true
    /// async/concurrency behind the same contract without changing runbook code.
    pub fn fanout<I, T, F>(
        &self,
        step_id: &str,
        items: Vec<WorkItem<I>>,
        _max_concurrency: usize,
        policy: PartialFailurePolicy,
        mut f: F,
    ) -> Result<FanoutOutcome<T>>
    where
        F: FnMut(I) -> Result<T>,
        T: Serialize + DeserializeOwned,
    {
        self.manifest.assert_step(step_id)?;
        let mut outcome = FanoutOutcome::default();
        for item in items {
            if let Some(value) = self.load_completed_item::<T>(step_id, &item.key)? {
                outcome.skipped_from_checkpoint.push(item.key.clone());
                outcome.completed.push(CompletedWorkItem {
                    key: item.key,
                    value,
                    skipped_from_checkpoint: true,
                });
                continue;
            }

            match f(item.input) {
                Ok(value) => {
                    self.write_completed_item(step_id, &item.key, &value)?;
                    outcome.completed.push(CompletedWorkItem {
                        key: item.key,
                        value,
                        skipped_from_checkpoint: false,
                    });
                }
                Err(error) => {
                    let message = error.to_string();
                    self.write_failed_item(step_id, &item.key, &message)?;
                    outcome.failed.push(FailedWorkItem {
                        key: item.key,
                        error: message.clone(),
                    });
                    if policy == PartialFailurePolicy::FailFast {
                        anyhow::bail!("runbook fanout {step_id:?} failed: {message}");
                    }
                }
            }
        }
        Ok(outcome)
    }

    fn load_completed_item<T: DeserializeOwned>(
        &self,
        step_id: &str,
        key: &WorkItemKey,
    ) -> Result<Option<T>> {
        let read = read_run_artifact_text(
            self.target,
            self.run_id,
            &item_leaf(self.manifest.id, step_id, key),
        );
        let RunArtifactRead::Ready { path, value: text } = read else {
            return Ok(None);
        };
        let json: Value = serde_json::from_str(&text)
            .with_context(|| format!("Could not parse runbook checkpoint {}", path.display()))?;
        if json.get("status").and_then(Value::as_str) != Some("completed") {
            return Ok(None);
        }
        let Some(value) = json.get("value") else {
            return Ok(None);
        };
        serde_json::from_value(value.clone())
            .with_context(|| format!("Could not decode runbook checkpoint {}", path.display()))
            .map(Some)
    }

    fn write_completed_item<T: Serialize>(
        &self,
        step_id: &str,
        key: &WorkItemKey,
        value: &T,
    ) -> Result<()> {
        let payload = json!({
            "status": "completed",
            "key": key,
            "value": value,
        });
        self.write_item(step_id, key, "completed work item", &payload)
            .map(|_| ())
    }

    fn write_failed_item(&self, step_id: &str, key: &WorkItemKey, error: &str) -> Result<()> {
        let payload = json!({
            "status": "failed",
            "key": key,
            "error": error,
        });
        self.write_item(step_id, key, "failed work item", &payload)
            .map(|_| ())
    }

    fn write_item(
        &self,
        step_id: &str,
        key: &WorkItemKey,
        label: &str,
        value: &Value,
    ) -> Result<RunArtifact> {
        let leaf = item_leaf(self.manifest.id, step_id, key);
        let value = with_runbook_metadata(value.clone(), self.manifest, self.run_id);
        write_run_artifact_json(self.target, self.run_id, &leaf, label, &value)
    }
}

fn item_leaf(runbook_id: &str, step_id: &str, key: &WorkItemKey) -> String {
    format!(
        "runbooks/{}/items/{}/{}.{}.json",
        runbook_id,
        sanitize_leaf(step_id),
        sanitize_leaf(&key.stable_id),
        sanitize_leaf(&key.content_hash),
    )
}

fn with_runbook_metadata(value: Value, manifest: &RunbookManifest, run_id: &str) -> Value {
    match value {
        Value::Object(mut object) => {
            object.insert(
                "schemaVersion".to_string(),
                json!(manifest.output_schema_version),
            );
            object.insert("runbookId".to_string(), json!(manifest.id));
            object.insert("runbookVersion".to_string(), json!(manifest.version));
            object.insert("toolName".to_string(), json!(manifest.owner_tool));
            object.insert("phase".to_string(), json!(manifest.phase.as_str()));
            object.insert("runId".to_string(), json!(run_id));
            Value::Object(object)
        }
        other => json!({
            "schemaVersion": manifest.output_schema_version,
            "runbookId": manifest.id,
            "runbookVersion": manifest.version,
            "toolName": manifest.owner_tool,
            "phase": manifest.phase.as_str(),
            "runId": run_id,
            "value": other,
        }),
    }
}

fn sanitize_leaf(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runbooks::manifest::{EngagementPhase, RunbookStepKind, RunbookStepManifest};

    const STEPS: &[RunbookStepManifest] = &[RunbookStepManifest {
        id: "fanout",
        label: "fan out",
        kind: RunbookStepKind::Fanout,
    }];

    const MANIFEST: RunbookManifest = RunbookManifest {
        id: "test-runbook",
        version: "v1",
        phase: EngagementPhase::Hunt,
        owner_tool: "agentic-sast:scan",
        title: "test",
        steps: STEPS,
        output_schema_version: "test.v1",
    };

    #[test]
    fn item_leaf_is_stable_and_sanitized() {
        let key = WorkItemKey::new("F:001", "abc/def");
        assert_eq!(
            item_leaf("rb", "vote step", &key),
            "runbooks/rb/items/vote-step/F-001.abc-def.json"
        );
    }

    #[test]
    fn metadata_wraps_non_object_values() {
        let value = with_runbook_metadata(json!([1, 2]), &MANIFEST, "r-1");
        assert_eq!(value["runbookId"], "test-runbook");
        assert_eq!(value["value"], json!([1, 2]));
    }
}
