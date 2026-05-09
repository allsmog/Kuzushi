use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepRuleFixture {
    pub name: String,
    pub body: String,
    pub should_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_fingerprint: Option<String>,
}

impl SemgrepRuleFixture {
    pub fn positive(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
            should_match: true,
            source_fingerprint: None,
        }
    }

    pub fn negative(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
            should_match: false,
            source_fingerprint: None,
        }
    }

    pub fn for_finding(mut self, fingerprint: impl Into<String>) -> Self {
        self.source_fingerprint = Some(fingerprint.into());
        self
    }
}
