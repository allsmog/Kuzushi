use super::DfdSecurityItem;

impl DfdSecurityItem {
    pub(crate) fn evidence_label(&self) -> String {
        if self.evidence_paths.contains(&self.evidence) {
            serde_json::Value::String(self.evidence.clone()).to_string()
        } else {
            self.evidence.clone()
        }
    }
}
