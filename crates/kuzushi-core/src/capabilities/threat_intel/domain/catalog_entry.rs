use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level wrapper read from a catalog TOML file. `schema_version`
/// is the operator-facing migration handle — when we change the entry
/// shape in a breaking way, bump this and gate parsing on it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CatalogFile {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default, rename = "entry")]
    pub entries: Vec<RawCatalogEntry>,
}

fn default_schema_version() -> String {
    "1".to_string()
}

/// A raw entry as it appears on disk. The `hunt_config` field is a
/// free-form `BTreeMap` so each hunt-specific subtable (e.g.
/// `[entry.taint_iris_next]`, `[entry.uaf_hunt]`) survives unchanged
/// across the load → dispatch boundary. Per-hunt knob validation
/// happens at dispatch time, not load time, so adding a new hunt
/// doesn't require touching the loader.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawCatalogEntry {
    pub id: String,
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub title: String,
    pub cwe: String,
    pub severity: String,
    #[serde(default)]
    pub provenance: String,
    #[serde(default)]
    pub source_repo: String,
    #[serde(default)]
    pub fix_commit: String,
    /// Discriminator pointing at one of the registered hunt modules.
    /// `apply` reads this to decide where to dispatch.
    pub hunt: String,
    /// All remaining TOML tables. The hunt-specific subtable is fished
    /// out by `dispatch` by indexing with the underscore form of
    /// `hunt` (e.g. `hunt = "uaf-hunt"` looks for `uaf_hunt`).
    #[serde(flatten)]
    pub hunt_config: BTreeMap<String, toml::Value>,
}

/// Validated entry produced by the loader after schema checks. Owns
/// the same data as `RawCatalogEntry` but with severity normalised to
/// the enum and the hunt discriminator parsed.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub id: String,
    pub cves: Vec<String>,
    pub title: String,
    pub cwe: String,
    pub severity: CatalogSeverity,
    pub provenance: String,
    pub source_repo: String,
    pub fix_commit: String,
    pub hunt: HuntKind,
    pub hunt_config: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CatalogSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl CatalogSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// Discriminator for which existing kuzushi-core hunt module a catalog
/// entry should dispatch to. The variants map 1:1 to the hunt tools
/// we already ship; `Unsupported` carries the raw string so we can
/// surface "entry asked for a hunt we don't recognise" without
/// crashing the apply pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HuntKind {
    UafHunt,
    TaintIrisNext,
    SystemsHunt,
    Variant,
    Unsupported(String),
}

impl HuntKind {
    // Infallible by design — unknown values map to `Unsupported`, so this
    // cannot implement `std::str::FromStr` (which requires an error type).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(raw: &str) -> Self {
        match raw {
            "uaf-hunt" => Self::UafHunt,
            "taint-iris-next" => Self::TaintIrisNext,
            "systems-hunt" => Self::SystemsHunt,
            "variant" => Self::Variant,
            other => Self::Unsupported(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::UafHunt => "uaf-hunt",
            Self::TaintIrisNext => "taint-iris-next",
            Self::SystemsHunt => "systems-hunt",
            Self::Variant => "variant",
            Self::Unsupported(raw) => raw,
        }
    }

    /// The expected key in `hunt_config` carrying the per-hunt
    /// subtable. TOML key is the underscore form (`taint_iris_next`)
    /// because the dash form isn't a valid TOML bare key.
    pub fn config_key(&self) -> &str {
        match self {
            Self::UafHunt => "uaf_hunt",
            Self::TaintIrisNext => "taint_iris_next",
            Self::SystemsHunt => "systems_hunt",
            Self::Variant => "variant",
            Self::Unsupported(raw) => raw,
        }
    }
}
