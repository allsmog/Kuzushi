use super::*;
use serde_json::{json, Value};

impl ShellApp {
    pub(super) fn spawn_source_review(&mut self, saving: bool) {
        if self.runtime_state.source_review_worker.is_some() {
            return;
        }
        let Some(form) = self.source_review_form() else {
            return;
        };
        let input = match source_review_input(form, saving) {
            Ok(input) => input,
            Err(error) => {
                self.source_review_form_mut().unwrap().notice = Some(error.to_string());
                return;
            }
        };
        let key = (form.target.clone(), form.finding_id);
        let config = self.config().clone();
        let worker = match start_source_worker(key, config, input, saving) {
            Ok(worker) => worker,
            Err(error) => {
                self.source_review_form_mut().unwrap().notice = Some(error);
                return;
            }
        };
        self.runtime_state.source_review_worker = Some(worker);
        self.source_review_form_mut().unwrap().mode = if saving {
            SourceReviewMode::Saving
        } else {
            SourceReviewMode::Capturing
        };
    }

    pub(crate) fn poll_source_review(&mut self) -> bool {
        let Some(worker) = self.runtime_state.source_review_worker.as_ref() else {
            return false;
        };
        if !worker.handle.as_ref().unwrap().is_finished() {
            return false;
        }
        let mut worker = self.runtime_state.source_review_worker.take().unwrap();
        let result = worker.handle.take().unwrap().join().unwrap_or_else(|_| {
            Err("Source review worker stopped. Inspect the ledger before retrying.".into())
        });
        self.finish_source_review(worker.key.clone(), worker.saving, result);
        true
    }

    fn finish_source_review(
        &mut self,
        key: (std::path::PathBuf, i64),
        saving: bool,
        result: Result<Value, String>,
    ) {
        let Some(form) = self.runtime_state.source_review_forms.get_mut(&key) else {
            return;
        };
        match result.and_then(|output| apply_source_review_output(form, saving, output)) {
            Ok(()) => {}
            Err(error) => {
                form.notice = Some(error);
                form.mode = if saving {
                    SourceReviewMode::Confirm
                } else {
                    SourceReviewMode::Intro
                };
            }
        }
        if saving && self.target() == Some(key.0.as_path()) {
            self.reset_findings_page_request();
        }
        if self.runtime_state.source_review_visible.as_ref() != Some(&key) {
            self.set_info_notice(
                "review",
                "Source review finished. Its captured target and draft remain available.",
            );
        }
    }
}

fn source_review_input(form: &SourceReviewForm, saving: bool) -> anyhow::Result<Value> {
    let mut input = json!({"finding":format!("generation:{}",form.finding_id),"op":"capture"});
    if saving {
        let capture = form
            .capture
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Capture source before deciding"))?;
        input = json!({"finding":format!("generation:{}",form.finding_id),"op":"decide",
            "sourceRef":capture["sourceRef"],"verdict":SOURCE_VERDICTS[form.verdict].0,"reason":form.reason.text()});
    }
    Ok(input)
}

fn apply_source_review_output(
    form: &mut SourceReviewForm,
    saving: bool,
    output: Value,
) -> Result<(), String> {
    let data = output["data"].clone();
    if saving {
        let id = data["decisionId"]
            .as_i64()
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                "No saved-decision receipt returned. Inspect the ledger before retrying."
                    .to_string()
            })?;
        form.decision_id = Some(id);
        form.mode = SourceReviewMode::Saved;
        form.notice = Some(format!("Decision #{id} saved against the captured source. Earlier decisions remain in history."));
    } else {
        data["sourceRef"]
            .as_str()
            .filter(|reference| !reference.is_empty())
            .ok_or_else(|| "No captured-source reference returned.".to_string())?;
        form.capture = Some(data);
        form.mode = SourceReviewMode::Reading;
        form.notice = None;
    }
    form.scroll = 0;
    Ok(())
}

fn start_source_worker(
    key: (std::path::PathBuf, i64),
    config: V2Config,
    input: Value,
    saving: bool,
) -> Result<SourceReviewWorker, String> {
    let cancel = kuzushi_core::ScanCancellation::default();
    let worker_cancel = cancel.clone();
    let target = key.0.clone();
    let handle = std::thread::Builder::new()
        .name("source-review".into())
        .spawn(move || {
            let workspace =
                kuzushi_core::WorkspaceTarget::new(target).map_err(|e| e.to_string())?;
            kuzushi_core::workspace::execute_source_review_action(
                &workspace,
                &config,
                input,
                Some(&worker_cancel),
            )
            .map_err(|e| format!("{e:#}"))
        })
        .map_err(|error| format!("Could not start source review: {error}"))?;
    Ok(SourceReviewWorker {
        key,
        saving,
        cancel,
        handle: Some(handle),
    })
}
