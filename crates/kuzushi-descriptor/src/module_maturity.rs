use serde::{Deserialize, Serialize};

/// Product-support tier for a module.
///
/// Maturity is distinct from visibility: hidden modules are implementation
/// details, while Labs and Compatibility modules remain explicitly callable
/// but do not occupy the default catalog or guided product surface.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleMaturity {
    /// Supported product capability. Eligible for default catalog, workflows,
    /// documentation, and release-quality regression gates.
    #[default]
    Core,
    /// Opt-in research capability. Callable by exact module/tool id, but kept
    /// out of the default catalog until it has product-level quality evidence.
    Labs,
    /// Retained integration or migration surface. Callable explicitly, but not
    /// presented as the recommended current product path.
    Compatibility,
}

impl ModuleMaturity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Labs => "labs",
            Self::Compatibility => "compatibility",
        }
    }

    pub fn is_core(self) -> bool {
        matches!(self, Self::Core)
    }
}
