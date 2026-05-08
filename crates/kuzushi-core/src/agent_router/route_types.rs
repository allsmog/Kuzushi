use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelRoute {
    pub primary: String,
    /// Reserved for future explicit-consent fallback support.
    ///
    /// Loading rejects non-empty values today so a stale config cannot
    /// silently route a Claude task to Codex/OpenAI or vice versa.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallbacks: Vec<String>,
}

impl ModelRoute {
    pub fn new(primary: impl Into<String>) -> Self {
        Self {
            primary: primary.into(),
            fallbacks: Vec::new(),
        }
    }

    /// Return the configured primary on the first attempt only.
    ///
    /// Non-zero attempts return `None` to uphold the no-silent-model-fallback
    /// policy. Same-model transport retries live inside concrete runtime
    /// adapters and reuse the exact same model string.
    pub fn pick(&self, attempt: u32) -> Option<&str> {
        if attempt == 0 {
            return Some(self.primary.as_str());
        }
        None
    }
}

#[derive(Debug, Clone, Default)]
pub struct AgentRouter {
    pub(crate) routes: BTreeMap<AgentRole, ModelRoute>,
    pub(crate) default_model: Option<String>,
    pub(crate) concurrency_caps: BTreeMap<String, u32>,
}
