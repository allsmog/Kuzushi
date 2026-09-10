use super::domain::validate_identifier;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A reference to an existing operator approval, never an approval by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowanceReferenceV1 {
    pub schema_version: u32,
    pub investigation_id: String,
    pub revision: u32,
    pub work_id: String,
}

impl AllowanceReferenceV1 {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.schema_version == 1, "unsupported allowance reference version");
        anyhow::ensure!(self.revision > 0, "allowance reference needs an approved revision");
        validate_identifier(&self.investigation_id)?;
        validate_identifier(&self.work_id)
    }
}
