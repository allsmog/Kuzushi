use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptionScope {
    Global,
    Workspace,
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "kebab-case")]
pub enum OptionTarget {
    All,
    Module(String),
    Tool(String),
}

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
        let scope = match self.scope {
            OptionScope::Global => "global",
            OptionScope::Workspace => "workspace",
            OptionScope::Session => "session",
        };
        let target = match &self.target {
            OptionTarget::All => "all".to_string(),
            OptionTarget::Module(module) => format!("module/{module}"),
            OptionTarget::Tool(tool) => format!("tool/{tool}"),
        };
        format!("{scope}/{target}")
    }

    pub(crate) fn from_storage_key(raw: &str) -> Result<Self> {
        let mut parts = raw.splitn(3, '/');
        let scope = match parts.next().unwrap_or_default() {
            "global" => OptionScope::Global,
            "workspace" => OptionScope::Workspace,
            "session" => OptionScope::Session,
            other => anyhow::bail!("unknown option scope {other:?}"),
        };
        let target_kind = parts
            .next()
            .context("option binding key is missing target kind")?;
        let target = match target_kind {
            "all" => OptionTarget::All,
            "module" => OptionTarget::Module(
                parts
                    .next()
                    .filter(|id| !id.trim().is_empty())
                    .context("module option binding key is missing module id")?
                    .to_string(),
            ),
            "tool" => OptionTarget::Tool(
                parts
                    .next()
                    .filter(|id| !id.trim().is_empty())
                    .context("tool option binding key is missing tool id")?
                    .to_string(),
            ),
            other => anyhow::bail!("unknown option target kind {other:?}"),
        };
        Ok(Self { scope, target })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ToolOptionStore {
    pub(crate) bindings: BTreeMap<OptionBinding, BTreeMap<String, Value>>,
}
