use super::{
    provider_admission::{ProviderAdmission, ADMISSION_PROTOCOL},
    ResponseTextObserver,
};
use anyhow::{Context, Result};
use kuzushi_core::{allowance::AllowanceBinding, ScanCancellation};
use serde_json::Value;
use std::process::ChildStdin;

#[derive(Clone, Default)]
pub(super) struct BridgeObservation {
    pub(super) text: Option<ResponseTextObserver>,
    pub(super) allowance: Option<AllowanceBinding>,
    requires_allowance: bool,
}

pub(super) struct BridgeStream {
    pub(super) text: Option<ResponseTextObserver>,
    pub(super) admission: Option<ProviderAdmission>,
}

impl BridgeObservation {
    pub(super) fn new(
        text: Option<&ResponseTextObserver>,
        allowance: Option<&AllowanceBinding>,
    ) -> Self {
        Self {
            text: text.cloned(),
            allowance: allowance.cloned(),
            requires_allowance: true,
        }
    }

    pub(super) fn prepare_request(&self, value: &mut Value) -> Result<()> {
        if self.text.is_some() || self.allowance.is_some() {
            value["responseEvents"] = serde_json::json!("text-v1");
        }
        self.prepare_admission(value)
    }

    fn prepare_admission(&self, value: &mut Value) -> Result<()> {
        if self.requires_allowance {
            require_model_allowance(self.allowance.as_ref())?;
        }
        let Some(allowance) = &self.allowance else {
            return Ok(());
        };
        let model = value["model"]
            .as_str()
            .context("provider admission requires an explicit model")?;
        allowance.validate_model(model)?;
        value["providerAdmission"] = serde_json::json!(ADMISSION_PROTOCOL);
        Ok(())
    }

    pub(super) fn admission(
        &self,
        stdin: Option<ChildStdin>,
        cancellation: Option<&ScanCancellation>,
    ) -> Result<Option<ProviderAdmission>> {
        let Some(allowance) = &self.allowance else {
            return Ok(None);
        };
        let stdin = stdin.context("provider admission requires bridge stdin")?;
        Ok(Some(ProviderAdmission::new(
            allowance.clone(),
            stdin,
            cancellation.cloned(),
        )))
    }
}

pub(super) fn require_model_allowance(
    allowance: Option<&AllowanceBinding>,
) -> Result<&AllowanceBinding> {
    allowance.ok_or_else(|| {
        anyhow::Error::new(kuzushi_core::RuntimeFailure::new(
            kuzushi_core::RuntimeFailureMetadata::new(
                kuzushi_core::RuntimeFailureClass::AllowanceRefused,
                None,
                None,
            ),
        ))
        .context("Model work requires an approved investigation allowance. Prepare and approve a finite plan first; no provider request started.")
    })
}

#[cfg(test)]
pub(super) fn transport_test_observation(
    observer: Option<&ResponseTextObserver>,
) -> BridgeObservation {
    BridgeObservation {
        text: observer.cloned(),
        ..Default::default()
    }
}
