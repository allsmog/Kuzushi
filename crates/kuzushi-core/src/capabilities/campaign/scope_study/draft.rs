//! Recover editable common settings without carrying a boundary's context binding.
use super::*;

impl ScopeStudyReceipt {
    /// Rebuild common draft settings while retaining the immutable approved cases.
    /// A different context revision requires a newly frozen scanner projection.
    pub fn draft_scan_input(&self) -> Result<Value> {
        common_draft_input(
            &self.scope_study.first()?.base_input,
            &self.scope_study.inherited_threat_model_ref,
        )
    }
}

fn common_draft_input(first: &Value, common_context: &Value) -> Result<Value> {
    let mut input = first.clone();
    let settings = input.as_object_mut().context("Scope input is malformed")?;
    settings.remove("scanScopeRef");
    settings.remove("threat_model_ref");
    if settings.get("threatModelRef") != Some(common_context) {
        settings.remove("threatModelDigestRef");
    }
    settings.insert("threatModelRef".into(), common_context.clone());
    Ok(input)
}

#[cfg(test)]
mod tests;
