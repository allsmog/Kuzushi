use super::{
    option_scope::{option_scope_storage_key, parse_option_scope},
    option_target::{option_target_storage_key, parse_option_binding_target},
    OptionScope, OptionTarget,
};
use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OptionBinding {
    pub scope: OptionScope,
    pub target: OptionTarget,
}

impl OptionBinding {
    pub fn new(scope: OptionScope, target: OptionTarget) -> Self {
        Self { scope, target }
    }
}

impl Serialize for OptionBinding {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.storage_key())
    }
}

impl<'de> Deserialize<'de> for OptionBinding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_storage_key(&raw).map_err(serde::de::Error::custom)
    }
}

impl OptionBinding {
    pub(crate) fn storage_key(&self) -> String {
        format!(
            "{}/{}",
            option_scope_storage_key(self.scope),
            option_target_storage_key(&self.target)
        )
    }

    pub(crate) fn from_storage_key(raw: &str) -> Result<Self> {
        let mut parts = raw.splitn(3, '/');
        let scope = parse_option_scope(parts.next().unwrap_or_default())?;
        let target = parse_option_binding_target(&mut parts)?;
        Ok(Self { scope, target })
    }
}
