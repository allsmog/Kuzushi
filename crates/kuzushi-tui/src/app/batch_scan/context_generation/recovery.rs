use super::*;
use kuzushi_core::capabilities::campaign::load_context_study;

impl StudyContextGeneration {
    pub(super) fn refresh_result(&mut self, target: &std::path::Path) {
        self.generated = None;
        self.result_error = None;
        let Some(receipt) = &self.receipt else {
            return;
        };
        match receipt.generated_context(target) {
            Ok(reference) => self.generated = reference,
            Err(error) => self.result_error = Some(format!("{error:#}")),
        }
    }
}

impl ShellApp {
    pub(crate) fn restore_context_generation(&mut self, target: &std::path::Path, id: &str) {
        match restore_context_form(target, id) {
            Ok(config) => {
                self.show_study_form(config);
                self.open_study_context_picker();
            }
            Err(error) => {
                self.router.campaign_mut().notice =
                    Some(format!("Context study unavailable: {error:#}"))
            }
        }
    }
}

fn restore_context_form(target: &std::path::Path, id: &str) -> Result<BatchScanConfig> {
    let receipt = load_context_study(target, id)?;
    let allowance = receipt.load_allowance(target)?;
    let mut config = BatchScanConfig::load(target, None);
    config.study.investigation_id = receipt.investigation_id.clone();
    if let Some(allowance) = allowance {
        config.study.restore_allowance(allowance);
    }
    let mut generation = StudyContextGeneration {
        campaign_id: Some(receipt.campaign_id.clone()),
        context_input: receipt.input.clone(),
        preparation_jobs: serde_json::to_value(&receipt.preparation_jobs)?,
        ..Default::default()
    };
    generation.record_receipt(receipt);
    generation.refresh_result(target);
    config.context_generation = Some(generation);
    Ok(config)
}
